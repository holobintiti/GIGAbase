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
            uint8 traitId = _computeTraitId(msg.sender, tokenId, i);

            nftOwnerOf[tokenId] = msg.sender;
            nftTraitOf[tokenId] = traitId;
            nftMintedAtBlock[tokenId] = block.number;
            _nftIdsByOwner[msg.sender].push(tokenId);
            _allNftIds.push(tokenId);
            tokenIds[i] = tokenId;
            emit GigaNftMinted(msg.sender, tokenId, traitId, block.number);
        }

        if (payWithEth && msg.value > 0) {
            uint256 feeWei = (msg.value * feeBps) / GGB_BPS_DENOM;
            uint256 toTreasury = msg.value - feeWei;
            treasuryBalance += toTreasury;
            if (feeWei > 0) {
                (bool sent,) = gigaFeeRecipient.call{value: feeWei}("");
                if (!sent) revert GGB_TransferFailed();
            }
        }
        emit GigaNftBatchMinted(msg.sender, tokenIds, block.number);
        return tokenIds;
    }

    /// @param tokenIds Token ids to query.
    /// @return owners Owners for each id.
    /// @return traits Trait for each id.
    /// @return mintedAtBlocks Mint block for each id.
    function getNftsBatch(uint256[] calldata tokenIds) external view returns (
        address[] memory owners,
        uint8[] memory traits,
        uint256[] memory mintedAtBlocks
    ) {
        uint256 n = tokenIds.length;
        owners = new address[](n);
        traits = new uint8[](n);
        mintedAtBlocks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 tid = tokenIds[i];
            owners[i] = nftOwnerOf[tid];
            traits[i] = nftTraitOf[tid];
            mintedAtBlocks[i] = nftMintedAtBlock[tid];
        }
    }

    /// @param accounts Addresses to query.
    /// @return balances GIGA balance for each account.
    function getGigaBalancesBatch(address[] calldata accounts) external view returns (uint256[] memory balances) {
        uint256 n = accounts.length;
        balances = new uint256[](n);
        for (uint256 i = 0; i < n; i++) balances[i] = balanceOfGiga[accounts[i]];
    }

    /// @return counts Per-trait mint count (index 0..15).
    function getTraitCounts() external view returns (uint256[] memory counts) {
        counts = new uint256[](GGB_NFT_TRAIT_COUNT);
        for (uint256 i = 0; i < _allNftIds.length; i++) {
            uint8 t = nftTraitOf[_allNftIds[i]];
            counts[t]++;
        }
    }

    /// @param account Wallet address.
    /// @return gigaBalance GIGA balance.
    /// @return nftCount Number of NFTs owned.
    /// @return nftIds Array of owned NFT ids.
    function getHolderStats(address account) external view returns (
        uint256 gigaBalance,
        uint256 nftCount,
        uint256[] memory nftIds
    ) {
        gigaBalance = balanceOfGiga[account];
        nftIds = _nftIdsByOwner[account];
        nftCount = nftIds.length;
    }

    /// @return Current block number.
    function currentBlockNumber() external view returns (uint256) {
        return block.number;
    }

    /// @param account Address to check.
    /// @return True if account holds >= GGB_HOLD_FOR_NFT and supply allows mint.
    function canMintNftForFree(address account) external view returns (bool) {
        return balanceOfGiga[account] >= GGB_HOLD_FOR_NFT && totalNftMinted < GGB_MAX_NFT_SUPPLY;
    }

    /// @param ethWei ETH amount in wei.
    /// @return gigaAmount GIGA that would be received (18 decimals).
    function quoteGigaForEth(uint256 ethWei) external view returns (uint256 gigaAmount) {
        if (gigaPriceWei == 0) return 0;
        return (ethWei * (10 ** GGB_DECIMALS)) / gigaPriceWei;
    }

    /// @param gigaAmount GIGA amount (18 decimals).
    /// @return ethWei ETH cost in wei.
    function quoteEthForGiga(uint256 gigaAmount) external view returns (uint256 ethWei) {
        if (gigaPriceWei == 0) return 0;
        return (gigaAmount * gigaPriceWei) / (10 ** GGB_DECIMALS);
    }

    function name() external pure returns (string memory) {
        return "GIGA";
    }

    function symbol() external pure returns (string memory) {
        return "GIGA";
    }

    function totalSupply() external view returns (uint256) {
        return totalGigaSupply;
    }

    /// @param ethWei ETH amount in wei.
    /// @return gigaReceived GIGA that would be minted.
    /// @return feeWei Fee that would go to fee recipient.
    /// @return treasuryWei Amount that would accrue to treasury.
    function getBuyQuote(uint256 ethWei) external view returns (uint256 gigaReceived, uint256 feeWei, uint256 treasuryWei) {
        if (gigaPriceWei == 0 || ethWei == 0) return (0, 0, 0);
        gigaReceived = (ethWei * (10 ** GGB_DECIMALS)) / gigaPriceWei;
        feeWei = (ethWei * feeBps) / GGB_BPS_DENOM;
        treasuryWei = ethWei - feeWei;
    }

    /// @return ethRequired ETH required to mint one NFT.
    /// @return gigaHoldRequired GIGA hold required to mint for free.
    /// @return canMintFree True if caller can mint without paying ETH.
    function getNftMintQuote(address account) external view returns (uint256 ethRequired, uint256 gigaHoldRequired, bool canMintFree) {
        ethRequired = nftMintPriceWei;
        gigaHoldRequired = GGB_HOLD_FOR_NFT;
        canMintFree = balanceOfGiga[account] >= GGB_HOLD_FOR_NFT && totalNftMinted < GGB_MAX_NFT_SUPPLY;
    }

    function getNftIdsByTrait(uint8 traitId) external view returns (uint256[] memory tokenIds) {
        if (traitId >= GGB_NFT_TRAIT_COUNT) return new uint256[](0);
        uint256 count = 0;
        for (uint256 i = 0; i < _allNftIds.length; i++) {
            if (nftTraitOf[_allNftIds[i]] == traitId) count++;
        }
        tokenIds = new uint256[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < _allNftIds.length; i++) {
            if (nftTraitOf[_allNftIds[i]] == traitId) {
                tokenIds[j] = _allNftIds[i];
                j++;
            }
        }
    }

    function getNftIdsByTraitPaginated(uint8 traitId, uint256 offset, uint256 limit) external view returns (uint256[] memory tokenIds) {
        if (traitId >= GGB_NFT_TRAIT_COUNT) return new uint256[](0);
        uint256[] memory full = new uint256[](_allNftIds.length);
        uint256 count = 0;
        for (uint256 i = 0; i < _allNftIds.length; i++) {
            if (nftTraitOf[_allNftIds[i]] == traitId) {
                full[count] = _allNftIds[i];
                count++;
            }
        }
        if (offset >= count) return new uint256[](0);
        uint256 end = offset + limit;
        if (end > count) end = count;
        uint256 n = end - offset;
        tokenIds = new uint256[](n);
        for (uint256 i = 0; i < n; i++) tokenIds[i] = full[offset + i];
    }

    struct NftView {
        uint256 tokenId;
        address owner;
        uint8 traitId;
        uint256 mintedAtBlock;
    }

    function getFullNftView(uint256 tokenId) external view returns (NftView memory v) {
        v.owner = nftOwnerOf[tokenId];
        if (v.owner == address(0)) revert GGB_NftNotFound();
        v.tokenId = tokenId;
        v.traitId = nftTraitOf[tokenId];
        v.mintedAtBlock = nftMintedAtBlock[tokenId];
    }

    function getFullNftViewBatch(uint256[] calldata tokenIds) external view returns (NftView[] memory views) {
        uint256 n = tokenIds.length;
        views = new NftView[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 tid = tokenIds[i];
            views[i] = NftView({
                tokenId: tid,
                owner: nftOwnerOf[tid],
                traitId: nftTraitOf[tid],
                mintedAtBlock: nftMintedAtBlock[tid]
            });
        }
    }

    /// @param count Number of most recently minted NFTs to return.
    /// @return tokenIds Token ids (newest first).
    /// @return owners Owners.
    /// @return traits Trait ids.
    function getRecentMints(uint256 count) external view returns (uint256[] memory tokenIds, address[] memory owners, uint8[] memory traits) {
        uint256 len = _allNftIds.length;
        if (len == 0) return (new uint256[](0), new address[](0), new uint8[](0));
        if (count > len) count = len;
        tokenIds = new uint256[](count);
        owners = new address[](count);
        traits = new uint8[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 tid = _allNftIds[len - 1 - i];
            tokenIds[i] = tid;
            owners[i] = nftOwnerOf[tid];
            traits[i] = nftTraitOf[tid];
        }
    }

    function getConfigSnapshotFull() external view returns (
        address gigaTreasury_,
        address gigaFeeRecipient_,
        address gigaMinter_,
        uint256 deployBlock_,
        uint256 gigaPriceWei_,
        uint256 nftMintPriceWei_,
        uint256 feeBps_,
        uint256 totalGigaSupply_,
        uint256 totalNftMinted_,
        uint256 treasuryBalance_,
        uint256 holdForNft_,
        bool gigaPaused_
    ) {
        return (
            gigaTreasury,
            gigaFeeRecipient,
            gigaMinter,
            deployBlock,
            gigaPriceWei,
            nftMintPriceWei,
            feeBps,
            totalGigaSupply,
            totalNftMinted,
            treasuryBalance,
            GGB_HOLD_FOR_NFT,
            gigaPaused
        );
    }

    function getNftCountForTrait(uint8 traitId) external view returns (uint256) {
        if (traitId >= GGB_NFT_TRAIT_COUNT) return 0;
        uint256 count = 0;
        for (uint256 i = 0; i < _allNftIds.length; i++) {
            if (nftTraitOf[_allNftIds[i]] == traitId) count++;
        }
        return count;
    }

    /// @return totalGiga Total GIGA supply.
    /// @return totalNft Total NFTs minted.
    /// @return treasuryAccrued Treasury balance.
    /// @return nftIdsLength Length of _allNftIds.
    function getGlobalStats() external view returns (uint256 totalGiga, uint256 totalNft, uint256 treasuryAccrued, uint256 nftIdsLength) {
        return (totalGigaSupply, totalNftMinted, treasuryBalance, _allNftIds.length);
    }

    /// @param ethWei ETH amount.
    /// @return gigaReceived GIGA from purchase.
    /// @return feeWei Fee to fee recipient.
    /// @return treasuryWei To treasury.
    function getSaleProceedsBreakdown(uint256 ethWei) external view returns (uint256 gigaReceived, uint256 feeWei, uint256 treasuryWei) {
        if (gigaPriceWei == 0) return (0, 0, 0);
        gigaReceived = (ethWei * (10 ** GGB_DECIMALS)) / gigaPriceWei;
        feeWei = (ethWei * feeBps) / GGB_BPS_DENOM;
        treasuryWei = ethWei - feeWei;
    }

    /// @param tokenIds NFT token ids.
    /// @return owners Owner for each id (zero if not minted).
    function getNftOwnerBatch(uint256[] calldata tokenIds) external view returns (address[] memory owners) {
        uint256 n = tokenIds.length;
        owners = new address[](n);
        for (uint256 i = 0; i < n; i++) owners[i] = nftOwnerOf[tokenIds[i]];
    }

    /// @return supply Current GIGA total supply.
    /// @return minted Current NFT count.
    /// @return remaining Remaining NFT supply (GGB_MAX_NFT_SUPPLY - minted).
    function getSupplyInfo() external view returns (uint256 supply, uint256 minted, uint256 remaining) {
        supply = totalGigaSupply;
        minted = totalNftMinted;
        remaining = minted >= GGB_MAX_NFT_SUPPLY ? 0 : GGB_MAX_NFT_SUPPLY - minted;
    }

    /// @param tokenId NFT token id.
    /// @return True if token exists (minted).
    function getNftExists(uint256 tokenId) external view returns (bool) {
        return tokenId > 0 && tokenId <= totalNftMinted && nftOwnerOf[tokenId] != address(0);
    }

    /// @return Number of NFTs that can still be minted.
    function getMintableNftCount() external view returns (uint256) {
        if (totalNftMinted >= GGB_MAX_NFT_SUPPLY) return 0;
        return GGB_MAX_NFT_SUPPLY - totalNftMinted;
    }

    /// @param fromId First token id (inclusive).
    /// @param toId Last token id (inclusive).
    /// @return tokenIds Ids in range that exist.
    /// @return owners Owners for each.
    /// @return traits Trait for each.
    function getNftRange(uint256 fromId, uint256 toId) external view returns (
        uint256[] memory tokenIds,
        address[] memory owners,
        uint8[] memory traits
    ) {
        if (fromId > toId || toId == 0) {
            return (new uint256[](0), new address[](0), new uint8[](0));
        }
        if (toId > totalNftMinted) toId = totalNftMinted;
        uint256 n = toId - fromId + 1;
        tokenIds = new uint256[](n);
        owners = new address[](n);
        traits = new uint8[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 tid = fromId + i;
            tokenIds[i] = tid;
            owners[i] = nftOwnerOf[tid];
            traits[i] = nftTraitOf[tid];
        }
    }

    /// @param accounts Addresses to query.
    /// @return gigaBalances GIGA balance per account.
    /// @return nftCounts NFT count per account.
    function getMultipleHolderStats(address[] calldata accounts) external view returns (
        uint256[] memory gigaBalances,
        uint256[] memory nftCounts
    ) {
        uint256 n = accounts.length;
        gigaBalances = new uint256[](n);
        nftCounts = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            gigaBalances[i] = balanceOfGiga[accounts[i]];
            nftCounts[i] = _nftIdsByOwner[accounts[i]].length;
        }
    }

    /// @param account Wallet to build dashboard for.
    function getDashboard(address account) external view returns (
        uint256 gigaBalance,
        uint256 nftCount,
        uint256[] memory nftIds,
        bool canMintFree,
        uint256 ethToMintOne,
        uint256 gigaHoldRequired
    ) {
        gigaBalance = balanceOfGiga[account];
        nftIds = _nftIdsByOwner[account];
        nftCount = nftIds.length;
        canMintFree = gigaBalance >= GGB_HOLD_FOR_NFT && totalNftMinted < GGB_MAX_NFT_SUPPLY;
        ethToMintOne = nftMintPriceWei;
        gigaHoldRequired = GGB_HOLD_FOR_NFT;
    }

    function getTreasuryBalance() external view returns (uint256) { return treasuryBalance; }
    function getFeeBps() external view returns (uint256) { return feeBps; }
    function getGigaPriceWei() external view returns (uint256) { return gigaPriceWei; }
    function getNftMintPriceWei() external view returns (uint256) { return nftMintPriceWei; }
    function isPaused() external view returns (bool) { return gigaPaused; }

    function decimals() external pure returns (uint8) { return GGB_DECIMALS; }
    function maxNftSupply() external pure returns (uint256) { return GGB_MAX_NFT_SUPPLY; }
    function holdForNft() external pure returns (uint256) { return GGB_HOLD_FOR_NFT; }
    function batchMintNftMax() external pure returns (uint256) { return GGB_BATCH_MINT_NFT_MAX; }
    function nftTraitCount() external pure returns (uint256) { return GGB_NFT_TRAIT_COUNT; }

    /// @param traitId Trait 0..15.
    /// @return count Number of NFTs with this trait.
    /// @return bps Rarity in basis points (count * 10000 / totalNftMinted) or 0 if none minted.
    function getTraitRarity(uint8 traitId) external view returns (uint256 count, uint256 bps) {
        if (traitId >= GGB_NFT_TRAIT_COUNT) return (0, 0);
        count = 0;
        for (uint256 i = 0; i < _allNftIds.length; i++) {
            if (nftTraitOf[_allNftIds[i]] == traitId) count++;
        }
        if (totalNftMinted == 0) return (count, 0);
        bps = (count * GGB_BPS_DENOM) / totalNftMinted;
    }

    /// @param ethWei ETH amount.
    /// @return giga GIGA received (before fee).
    /// @return feeWei Fee portion.
    /// @return treasuryWei Treasury portion.
    function getBuySimulation(uint256 ethWei) external view returns (uint256 giga, uint256 feeWei, uint256 treasuryWei) {
        if (gigaPriceWei == 0) return (0, 0, 0);
        giga = (ethWei * (10 ** GGB_DECIMALS)) / gigaPriceWei;
        feeWei = (ethWei * feeBps) / GGB_BPS_DENOM;
        treasuryWei = ethWei - feeWei;
    }

    receive() external payable {
        if (msg.value > 0) treasuryBalance += msg.value;
    }
}

// -----------------------------------------------------------------------------
// GIGAbase — Function reference (for integrators)
// -----------------------------------------------------------------------------
// WRITE (state-changing):
//   buyGiga() payable — buy GIGA with ETH
//   transferGiga(to, amount) — transfer GIGA
//   mintGiga(to, amount) — minter: mint GIGA
//   mintGigaBatch(tos, amounts) — minter: batch mint GIGA
//   burnGiga(amount) — burn own GIGA
//   mintNft() payable — mint one NFT (ETH or hold)
//   mintNftWithTrait(traitId) — minter: mint NFT with trait
//   mintNftBatch(count) payable — mint up to 8 NFTs
//   transferNft(to, tokenId) — transfer NFT
//   withdrawTreasury() — owner/treasury: withdraw treasury balance
//   setPaused(paused), setFeeRecipient(addr), setMinter(addr)
//   setGigaPriceWei(price), setNftMintPriceWei(price), setFeeBps(bps)
// VIEW (no state change):
//   name(), symbol(), totalSupply() — token metadata
//   balanceOfGiga(addr), getGigaBalancesBatch(addrs)
//   getNft(tokenId), getNftIdsByOwner(addr), getAllNftIds()
//   getNftIdsPaginated(offset, limit), getNftsBatch(ids)
//   getFullNftView(tokenId), getFullNftViewBatch(ids)
//   getNftOwnerBatch(ids), getNftIdsByTrait(traitId), getNftIdsByTraitPaginated(traitId, offset, limit)
//   getNftCountForTrait(traitId), getTraitCounts()
//   getHolderStats(addr), getMultipleHolderStats(addrs)
//   getConfigSnapshot(), getConfigSnapshotFull()
//   getGlobalStats(), getSupplyInfo(), getMintableNftCount()
//   getBuyQuote(ethWei), getSaleProceedsBreakdown(ethWei), getNftMintQuote(addr)
//   quoteGigaForEth(ethWei), quoteEthForGiga(gigaAmount)
//   canMintNftForFree(addr), getNftExists(tokenId)
//   getRecentMints(count), getNftRange(fromId, toId), currentBlockNumber()
// -----------------------------------------------------------------------------
//
// EVENTS (indexed where shown):
//   GigaTransfer(from, to, amount, atBlock)
//   GigaMint(to, amount, atBlock)
//   GigaBurn(from, amount, atBlock)
//   GigaPurchased(buyer, ethSpent, gigaReceived, atBlock)
//   GigaNftMinted(to, tokenId, traitId, atBlock)
//   GigaNftTransfer(from, to, tokenId, atBlock)
//   GigaNftPurchased(buyer, tokenId, ethSpent, atBlock)
//   TreasuryWithdrawn(to, amountWei, atBlock)
//   FeeRecipientUpdated(previous, current)
//   MinterUpdated(previous, current)
//   PauseToggled(paused)
//   GigaPriceUpdated(previousWei, newWei)
//   NftMintPriceUpdated(previousWei, newWei)
//   GigaBatchMint(to, totalAmount, atBlock)
//   GigaNftBatchMinted(to, tokenIds, atBlock)
//
// IMMUTABLE (set in constructor, never change):
//   gigaTreasury — receives treasury withdrawals
//   gigaMinterRole — constructor-set minter role address (reference)
//   deployBlock — block number at deploy
//   chainNonce — keccak256 of chainid, timestamp, contract address
//
// CONFIGURABLE (owner can update):
//   gigaFeeRecipient — receives fee share on buy and NFT mint
//   gigaMinter — can mint GIGA and mint NFT with specific trait
//   gigaPriceWei — wei per full GIGA token (18 decimals)
//   nftMintPriceWei — wei to mint one NFT when paying with ETH
//   feeBps — basis points taken as fee (max 1000 = 10%)
//   gigaPaused — when true, buy/transfer/mint revert
//
// INTEGRATION CHECKLIST:
// 1. Deploy with no constructor args; treasury, fee recipient, minter are set to fixed addresses.
// 2. Optionally call setFeeRecipient / setMinter / setGigaPriceWei / setNftMintPriceWei / setFeeBps as owner.
// 3. Users connect wallet; call buyGiga() with ETH to get GIGA.
// 4. Users with enough GIGA can mintNft() with no ETH; others send nftMintPriceWei.
// 5. Frontend can use quoteGigaForEth, getBuyQuote, getNftMintQuote for display.
// 6. Treasury balance accrues from buys and NFT mints; owner or gigaTreasury calls withdrawTreasury().
// 7. NFT trait is random 0..15 on mint (or set by minter via mintNftWithTrait).
// 8. GGB_HOLD_FOR_NFT = 1000e18; holding that much GIGA allows free NFT mint.
// 9. Max 10000 NFTs; batch mint up to 8 per tx via mintNftBatch(count).
// 10. All role addresses in constructor are unique and not reused from other contracts.
//
// SECURITY:
// - ReentrancyGuard on all payable and state-changing external functions.
