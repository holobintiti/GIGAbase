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
