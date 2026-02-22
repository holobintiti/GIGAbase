// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GIGAbase
 * @notice Memecoin ledger with an attached NFT collection. Buy GIGA with ETH; mint NFTs by holding GIGA or paying ETH. Treasury and fee recipient receive a share of sales. No upgrade path; all role addresses set at deploy.
 * @dev Uses immutable for treasury and minter role; fee recipient and minter address are updatable by owner. ReentrancyGuard on all payable and state-changing paths. GIGA has 18 decimals; NFT traits are 0..15.
 *
 * User flows:
 * - Buy GIGA: send ETH to buyGiga(), receive GIGA at current gigaPriceWei; fee goes to fee recipient, rest to treasury balance.
 * - Transfer GIGA: transferGiga(to, amount).
 * - Mint NFT: call mintNft() with no ETH if balance >= GGB_HOLD_FOR_NFT, or send >= nftMintPriceWei to mint with ETH.
 * - Mint multiple NFTs: mintNftBatch(count) with ETH or sufficient GIGA hold.
 * - Withdraw treasury: owner or gigaTreasury calls withdrawTreasury().
 *
 * Security: No delegatecall. All ETH flows use explicit checks and ReentrancyGuard. Owner can pause, set prices, and update fee recipient/minter.
 */

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/access/Ownable.sol";

contract GIGAbase is ReentrancyGuard, Ownable {

    event GigaTransfer(address indexed from, address indexed to, uint256 amount, uint256 atBlock);
    event GigaMint(address indexed to, uint256 amount, uint256 atBlock);
    event GigaBurn(address indexed from, uint256 amount, uint256 atBlock);
    event GigaPurchased(address indexed buyer, uint256 ethSpent, uint256 gigaReceived, uint256 atBlock);
    event GigaNftMinted(address indexed to, uint256 indexed tokenId, uint8 traitId, uint256 atBlock);
    event GigaNftTransfer(address indexed from, address indexed to, uint256 indexed tokenId, uint256 atBlock);
    event GigaNftPurchased(address indexed buyer, uint256 indexed tokenId, uint256 ethSpent, uint256 atBlock);
    event TreasuryWithdrawn(address indexed to, uint256 amountWei, uint256 atBlock);
    event FeeRecipientUpdated(address indexed previous, address indexed current);
    event MinterUpdated(address indexed previous, address indexed current);
    event PauseToggled(bool paused);
    event GigaPriceUpdated(uint256 previousWei, uint256 newWei);
    event NftMintPriceUpdated(uint256 previousWei, uint256 newWei);
    event GigaBatchMint(address indexed to, uint256 totalAmount, uint256 atBlock);
    event GigaNftBatchMinted(address indexed to, uint256[] tokenIds, uint256 atBlock);

    // -------------------------------------------------------------------------
    // ERRORS (revert with custom errors for gas and clarity)
    // -------------------------------------------------------------------------
    // GGB_ZeroAddress: Operation required a non-zero address.
    // GGB_ZeroAmount: Amount was zero.
    // GGB_TransferFailed: ETH transfer to fee recipient or treasury failed.
    // GGB_InsufficientBalance: Caller balance too low for transfer/burn.
    // GGB_InsufficientPayment: ETH sent too low for purchase.
    // GGB_Paused: Contract is paused.
    // GGB_NotMinter: Caller is not minter or owner.
    // GGB_MaxNftSupply: NFT supply cap reached.
    // GGB_NftNotFound: Token id not minted or invalid.
    // GGB_NotNftOwner: Caller does not own the NFT.
    // GGB_HoldRequired: Need to hold GGB_HOLD_FOR_NFT GIGA to mint for free.
    // GGB_InvalidTrait: Trait id out of range or array length mismatch.
    // GGB_PriceZero: Price cannot be set to zero.
    // -------------------------------------------------------------------------

    error GGB_ZeroAddress();
    error GGB_ZeroAmount();
    error GGB_TransferFailed();
    error GGB_InsufficientBalance();
    error GGB_InsufficientPayment();
    error GGB_Paused();
    error GGB_NotMinter();
    error GGB_MaxNftSupply();
    error GGB_NftNotFound();
    error GGB_NotNftOwner();
    error GGB_HoldRequired();
    error GGB_InvalidTrait();
    error GGB_PriceZero();

    // -------------------------------------------------------------------------
    // CONSTANTS (GIGA token and NFT collection)
    // -------------------------------------------------------------------------
    // GGB_DECIMALS: GIGA token uses 18 decimals.
    // GGB_BPS_DENOM: Basis points denominator (10000 = 100%).
    // GGB_MAX_FEE_BPS: Maximum fee allowed (10%).
    // GGB_MAX_NFT_SUPPLY: Cap on number of NFTs (10000).
    // GGB_NFT_TRAIT_COUNT: Traits are 0..15.
    // GGB_BATCH_MINT_NFT_MAX: Max NFTs per mintNftBatch call.
    // GGB_DOMAIN_SALT: Chain/domain salt for trait RNG.
    // -------------------------------------------------------------------------

    uint8 public constant GGB_DECIMALS = 18;
    uint256 public constant GGB_BPS_DENOM = 10000;
    uint256 public constant GGB_MAX_FEE_BPS = 1000;
    uint256 public constant GGB_MAX_NFT_SUPPLY = 10000;
    uint256 public constant GGB_NFT_TRAIT_COUNT = 16;
    uint256 public constant GGB_BATCH_MINT_NFT_MAX = 8;
    uint256 public constant GGB_DOMAIN_SALT = 0x9f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0e2f4a6;

    address public immutable gigaTreasury;
    address public immutable gigaMinterRole;
    uint256 public immutable deployBlock;
    bytes32 public immutable chainNonce;

    address public gigaFeeRecipient;
    address public gigaMinter;
    uint256 public gigaPriceWei;
    uint256 public nftMintPriceWei;
    uint256 public feeBps;
    bool public gigaPaused;
    uint256 public totalGigaSupply;
    uint256 public totalNftMinted;
    uint256 public treasuryBalance;

    mapping(address => uint256) public balanceOfGiga;
    mapping(uint256 => address) public nftOwnerOf;
    mapping(uint256 => uint8) public nftTraitOf;
    mapping(uint256 => uint256) public nftMintedAtBlock;
    mapping(address => uint256[]) private _nftIdsByOwner;

    uint256[] private _allNftIds;

    modifier whenNotPaused() {
        if (gigaPaused) revert GGB_Paused();
        _;
    }

    modifier onlyMinterRole() {
        if (msg.sender != gigaMinter && msg.sender != owner()) revert GGB_NotMinter();
        _;
    }

    constructor() {
        gigaTreasury = address(0x7b3E9f1A2c4D6e8F0a2B4c6D8e0F2a4B6c8D0e2);
        gigaFeeRecipient = address(0x8c4F0a2B3d5E7f9A1b3C5d7E9f1A3b5C7d9E1f);
        gigaMinterRole = address(0x9d5A1b3C4e6F8a0B2c4D6e8F0a2B4c6D8e0F2);
        gigaMinter = address(0xae6B2c4D5f7A9b1C3d5E7f9A1b3C5d7E9f1A3);
        deployBlock = block.number;
        chainNonce = keccak256(abi.encodePacked("GIGAbase_", block.chainid, block.timestamp, address(this)));
        gigaPriceWei = 1e12;
        nftMintPriceWei = 1e15;
        feeBps = 500;
    }

    /// @notice Pause or unpause buys, transfers, mints. Owner only.
    function setPaused(bool paused) external onlyOwner {
        gigaPaused = paused;
        emit PauseToggled(paused);
    }

    /// @notice Set fee recipient (receives fee share on buy and NFT mint). Owner only.
    function setFeeRecipient(address newRecipient) external onlyOwner {
        if (newRecipient == address(0)) revert GGB_ZeroAddress();
        address prev = gigaFeeRecipient;
        gigaFeeRecipient = newRecipient;
        emit FeeRecipientUpdated(prev, newRecipient);
    }

    /// @notice Set minter address (can mint GIGA and mint NFT with specific trait). Owner only.
    function setMinter(address newMinter) external onlyOwner {
        if (newMinter == address(0)) revert GGB_ZeroAddress();
        address prev = gigaMinter;
        gigaMinter = newMinter;
        emit MinterUpdated(prev, newMinter);
    }

    /// @notice Set GIGA price in wei per full token (18 decimals). Owner only.
    function setGigaPriceWei(uint256 newPrice) external onlyOwner {
        if (newPrice == 0) revert GGB_PriceZero();
        uint256 prev = gigaPriceWei;
        gigaPriceWei = newPrice;
        emit GigaPriceUpdated(prev, newPrice);
    }

    /// @notice Set NFT mint price in wei (when paying with ETH). Owner only.
    function setNftMintPriceWei(uint256 newPrice) external onlyOwner {
        uint256 prev = nftMintPriceWei;
        nftMintPriceWei = newPrice;
        emit NftMintPriceUpdated(prev, newPrice);
    }

    /// @notice Set protocol fee in basis points (max GGB_MAX_FEE_BPS). Owner only.
    function setFeeBps(uint256 newBps) external onlyOwner {
        if (newBps > GGB_MAX_FEE_BPS) revert GGB_InvalidTrait();
        feeBps = newBps;
    }

    /// @notice Purchase GIGA tokens with ETH. Fee is sent to fee recipient; remainder accrues to treasury balance.
    /// @return gigaReceived Amount of GIGA minted (18 decimals).
    function buyGiga() external payable whenNotPaused nonReentrant returns (uint256 gigaReceived) {
        if (msg.value == 0) revert GGB_ZeroAmount();
        if (gigaPriceWei == 0) revert GGB_PriceZero();
        gigaReceived = (msg.value * (10 ** GGB_DECIMALS)) / gigaPriceWei;
        if (gigaReceived == 0) revert GGB_InsufficientPayment();

        uint256 feeWei = (msg.value * feeBps) / GGB_BPS_DENOM;
        uint256 toTreasury = msg.value - feeWei;
        treasuryBalance += toTreasury;
        if (feeWei > 0) {
            (bool sent,) = gigaFeeRecipient.call{value: feeWei}("");
            if (!sent) revert GGB_TransferFailed();
        }

        totalGigaSupply += gigaReceived;
        balanceOfGiga[msg.sender] += gigaReceived;
        emit GigaMint(msg.sender, gigaReceived, block.number);
        emit GigaPurchased(msg.sender, msg.value, gigaReceived, block.number);
        return gigaReceived;
    }

    /// @notice Transfer GIGA to another address.
    /// @param to Recipient (cannot be zero).
    /// @param amount Amount in 18 decimals.
    function transferGiga(address to, uint256 amount) external whenNotPaused nonReentrant {
        if (to == address(0)) revert GGB_ZeroAddress();
        if (amount == 0) revert GGB_ZeroAmount();
        if (balanceOfGiga[msg.sender] < amount) revert GGB_InsufficientBalance();

        balanceOfGiga[msg.sender] -= amount;
        balanceOfGiga[to] += amount;
        emit GigaTransfer(msg.sender, to, amount, block.number);
    }

    /// @notice Mint GIGA to an address. Minter or owner only.
    /// @param to Recipient.
    /// @param amount Amount in 18 decimals.
    function mintGiga(address to, uint256 amount) external onlyMinterRole whenNotPaused nonReentrant {
        if (to == address(0)) revert GGB_ZeroAddress();
        if (amount == 0) revert GGB_ZeroAmount();

        totalGigaSupply += amount;
        balanceOfGiga[to] += amount;
        emit GigaMint(to, amount, block.number);
    }

    /// @notice Burn GIGA from caller. Reduces total supply.
    /// @param amount Amount in 18 decimals.
    function burnGiga(uint256 amount) external whenNotPaused nonReentrant {
        if (amount == 0) revert GGB_ZeroAmount();
        if (balanceOfGiga[msg.sender] < amount) revert GGB_InsufficientBalance();

        balanceOfGiga[msg.sender] -= amount;
        totalGigaSupply -= amount;
        emit GigaBurn(msg.sender, amount, block.number);
    }

    uint256 public constant GGB_HOLD_FOR_NFT = 1000 * (10 ** 18);

    /// @notice Mint one NFT. Either send >= nftMintPriceWei ETH or hold >= GGB_HOLD_FOR_NFT GIGA.
    /// @return tokenId The minted NFT token id.
    function mintNft() external payable whenNotPaused nonReentrant returns (uint256 tokenId) {
        if (totalNftMinted >= GGB_MAX_NFT_SUPPLY) revert GGB_MaxNftSupply();

        bool payWithEth = msg.value >= nftMintPriceWei;
        if (!payWithEth) {
            if (balanceOfGiga[msg.sender] < GGB_HOLD_FOR_NFT) revert GGB_HoldRequired();
        }

        tokenId = totalNftMinted + 1;
        totalNftMinted = tokenId;

        uint8 traitId = _computeTraitId(msg.sender, tokenId, 0);

        nftOwnerOf[tokenId] = msg.sender;
        nftTraitOf[tokenId] = traitId;
        nftMintedAtBlock[tokenId] = block.number;
        _nftIdsByOwner[msg.sender].push(tokenId);
        _allNftIds.push(tokenId);

        if (payWithEth) {
            uint256 feeWei = (msg.value * feeBps) / GGB_BPS_DENOM;
            uint256 toTreasury = msg.value - feeWei;
            treasuryBalance += toTreasury;
            if (feeWei > 0) {
                (bool sent,) = gigaFeeRecipient.call{value: feeWei}("");
                if (!sent) revert GGB_TransferFailed();
            }
            emit GigaNftPurchased(msg.sender, tokenId, msg.value, block.number);
        }
        emit GigaNftMinted(msg.sender, tokenId, traitId, block.number);
        return tokenId;
    }

    /// @notice Mint one NFT with a specific trait. Minter only.
    /// @param traitId Trait index 0..GGB_NFT_TRAIT_COUNT-1.
    /// @return tokenId The minted NFT token id.
    function mintNftWithTrait(uint8 traitId) external onlyMinterRole whenNotPaused nonReentrant returns (uint256 tokenId) {
        if (traitId >= GGB_NFT_TRAIT_COUNT) revert GGB_InvalidTrait();
        if (totalNftMinted >= GGB_MAX_NFT_SUPPLY) revert GGB_MaxNftSupply();

        tokenId = totalNftMinted + 1;
        totalNftMinted = tokenId;

        nftOwnerOf[tokenId] = msg.sender;
        nftTraitOf[tokenId] = traitId;
        nftMintedAtBlock[tokenId] = block.number;
        _nftIdsByOwner[msg.sender].push(tokenId);
        _allNftIds.push(tokenId);

        emit GigaNftMinted(msg.sender, tokenId, traitId, block.number);
        return tokenId;
    }

    /// @notice Transfer NFT to another address. Caller must own the NFT.
    /// @param to New owner (cannot be zero).
    /// @param tokenId NFT token id.
    function transferNft(address to, uint256 tokenId) external whenNotPaused nonReentrant {
        if (to == address(0)) revert GGB_ZeroAddress();
        if (nftOwnerOf[tokenId] != msg.sender) revert GGB_NotNftOwner();

        nftOwnerOf[tokenId] = to;
        _nftIdsByOwner[to].push(tokenId);
        _removeNftFromOwner(msg.sender, tokenId);
        emit GigaNftTransfer(msg.sender, to, tokenId, block.number);
    }

    function _removeNftFromOwner(address owner_, uint256 tokenId) internal {
        uint256[] storage ids = _nftIdsByOwner[owner_];
        for (uint256 i = 0; i < ids.length; i++) {
            if (ids[i] == tokenId) {
                ids[i] = ids[ids.length - 1];
                ids.pop();
                break;
            }
        }
    }

    function _computeTraitId(address minter_, uint256 tokenId, uint256 nonce) internal view returns (uint8) {
        return uint8(uint256(keccak256(abi.encodePacked(block.prevrandao, minter_, tokenId, nonce, GGB_DOMAIN_SALT))) % GGB_NFT_TRAIT_COUNT);
    }

    /// @notice Withdraw accumulated treasury balance to gigaTreasury. Callable by owner or gigaTreasury.
    function withdrawTreasury() external nonReentrant {
        if (msg.sender != owner() && msg.sender != gigaTreasury) revert GGB_ZeroAddress();
        uint256 amount = treasuryBalance;
        if (amount == 0) revert GGB_ZeroAmount();
        treasuryBalance = 0;
        (bool sent,) = gigaTreasury.call{value: amount}("");
        if (!sent) revert GGB_TransferFailed();
        emit TreasuryWithdrawn(gigaTreasury, amount, block.number);
    }

    /// @param tokenId NFT token id.
    /// @return owner_ Current owner.
    /// @return traitId Trait index 0..15.
    /// @return mintedAtBlock Block at mint.
    function getNft(uint256 tokenId) external view returns (address owner_, uint8 traitId, uint256 mintedAtBlock) {
        owner_ = nftOwnerOf[tokenId];
        if (owner_ == address(0)) revert GGB_NftNotFound();
        return (owner_, nftTraitOf[tokenId], nftMintedAtBlock[tokenId]);
    }

    /// @param owner_ Wallet address.
    /// @return Array of NFT token ids owned.
    function getNftIdsByOwner(address owner_) external view returns (uint256[] memory) {
        return _nftIdsByOwner[owner_];
    }

    /// @return All minted NFT token ids.
    function getAllNftIds() external view returns (uint256[] memory) {
        return _allNftIds;
    }

    /// @param offset Start index.
    /// @param limit Max number of ids to return.
    /// @return tokenIds Slice of _allNftIds.
    function getNftIdsPaginated(uint256 offset, uint256 limit) external view returns (uint256[] memory) {
        uint256 len = _allNftIds.length;
        if (offset >= len) return new uint256[](0);
        uint256 end = offset + limit;
        if (end > len) end = len;
        uint256 n = end - offset;
        uint256[] memory out = new uint256[](n);
        for (uint256 i = 0; i < n; i++) out[i] = _allNftIds[offset + i];
        return out;
    }

    /// @return Snapshot of main config (treasury, fee recipient, minter, prices, supply, paused).
    function getConfigSnapshot() external view returns (
        address gigaTreasury_,
        address gigaFeeRecipient_,
        address gigaMinter_,
        uint256 deployBlock_,
        uint256 gigaPriceWei_,
        uint256 nftMintPriceWei_,
        uint256 totalGigaSupply_,
        uint256 totalNftMinted_,
        uint256 treasuryBalance_,
        bool gigaPaused_
    ) {
        return (
            gigaTreasury,
            gigaFeeRecipient,
            gigaMinter,
            deployBlock,
            gigaPriceWei,
            nftMintPriceWei,
            totalGigaSupply,
            totalNftMinted,
            treasuryBalance,
            gigaPaused
        );
    }

    /// @notice Mint GIGA to multiple addresses. Minter or owner only.
    /// @param tos Recipients (same length as amounts).
    /// @param amounts Amounts in 18 decimals per recipient.
    function mintGigaBatch(address[] calldata tos, uint256[] calldata amounts) external onlyMinterRole whenNotPaused nonReentrant {
        if (tos.length != amounts.length) revert GGB_InvalidTrait();
        uint256 total = 0;
        for (uint256 i = 0; i < tos.length; i++) {
            if (tos[i] == address(0)) revert GGB_ZeroAddress();
            if (amounts[i] == 0) continue;
            balanceOfGiga[tos[i]] += amounts[i];
            total += amounts[i];
            emit GigaMint(tos[i], amounts[i], block.number);
        }
        if (total > 0) {
            totalGigaSupply += total;
            emit GigaBatchMint(msg.sender, total, block.number);
        }
    }

    /// @notice Mint multiple NFTs in one tx. Pay with ETH (count * nftMintPriceWei) or hold count * GGB_HOLD_FOR_NFT GIGA.
    /// @param count Number of NFTs to mint (max GGB_BATCH_MINT_NFT_MAX).
    /// @return tokenIds Minted token ids.
    function mintNftBatch(uint256 count) external payable whenNotPaused nonReentrant returns (uint256[] memory tokenIds) {
        if (count == 0 || count > GGB_BATCH_MINT_NFT_MAX) revert GGB_InvalidTrait();
        if (totalNftMinted + count > GGB_MAX_NFT_SUPPLY) revert GGB_MaxNftSupply();

        uint256 requiredEth = nftMintPriceWei * count;
        bool payWithEth = msg.value >= requiredEth;
        if (!payWithEth) {
            if (balanceOfGiga[msg.sender] < GGB_HOLD_FOR_NFT * count) revert GGB_HoldRequired();
        }

        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 tokenId = totalNftMinted + 1;
            totalNftMinted = tokenId;
