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
