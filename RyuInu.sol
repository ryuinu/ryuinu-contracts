// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./access/RoleAccessControl.sol";
import "./token/ERC20/utils/SafeERC20.sol";
import "./token/ERC20/AnyswapERC20.sol";
import "./token/ERC20/extensions/ERC20Votes.sol";
import ".//utils/math/SafeMath.sol";

/**
 * @dev Compatible with ERC20
 * ADMINS, OPERATORS, isMinters can mint or burn tokens
 */

contract RyuInu is RoleAccessControl, ERC20Votes {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;
    // max supply ERC20Votes support is `type(uint224).max` (2^224^ - 1)
    uint224 public maxSupply = type(uint224).max;
    // transfer fee percent
    uint256 public transferFee = 1;
    // max transfer fee percent
    uint256 public MAX_TRANSFER_FEE = 10;
    // address to send transfer fees to
    address public feeAddress;
    // addresses to exclude from transfer fees
    mapping (address => bool) private _isExcludedFromFee;

    constructor (string memory _name, string memory _symbol, uint8 _decimals, address _underlying, address _vault)
        AnyswapERC20(_name, _symbol, _decimals, _underlying, _vault)
    {
        _setupRole(ADMINS, _msgSender());
        excludeFromFee(_msgSender());
        // initially set feeAddress to _msgSender()
        feeAddress = _msgSender();
    }

    /**
     * @dev Auth to mint, burn, swapIn
     */
    modifier onlyAuth() override {
        require(isMinter[_msgSender()] || hasRole(OPERATORS, _msgSender()), "AnyswapERC20:onlyAuth() FORBIDDEN");
        _;
    }

    /**
     *@dev Auth to setVaultOnly, initVault, setMinter, setVault, applyVault, applyMinter, revokeMinter, changeVault, changeMPCOwner, depositVault, withdrawVault
     * ADMINS have this auth in case there is a need to change anything
     */
    modifier onlyVault() override {
        require(_msgSender() == mpc() || hasRole(ADMINS, _msgSender()), "AnyswapERC20:onlyVault() FORBIDDEN");
        _;
    }

    /**
     * @dev Transfers sends transferFee to feeAddress and remainder to recipient
     */
    function _transfer(address sender, address recipient, uint256 amount) internal virtual override {
        uint256 balance = balanceOf(sender);
        require(balance >= amount, "_transfer: transfer amount exceeds balance");

        // no transfer fees for excluded addresses or if sending to vaultAddress
        if (_isExcludedFromFee[sender] || recipient == feeAddress) {
            super._transfer(sender, recipient, amount);
        } else {
            uint256 feeAmount = amount.mul(transferFee).div(100);
            uint256 recipientAmount = amount.sub(feeAmount);
            require(amount == recipientAmount + feeAmount, "_transfer: value invalid");

            _beforeTokenTransfer(sender, recipient, amount);

            _balances[sender] = balanceOf(sender).sub(amount, '_transfer: transfer amount exceeds balance');
            _balances[recipient] = balanceOf(recipient).add(recipientAmount);
            _balances[feeAddress] = balanceOf(feeAddress).add(feeAmount);
            emit Transfer(sender, recipient, recipientAmount);
            emit Transfer(sender, feeAddress, feeAmount);

            _afterTokenTransfer(sender, recipient, recipientAmount);
            _afterTokenTransfer(sender, feeAddress, feeAmount);
        }
    }

    /**
     * @dev OPERATORS can transfer without fee
     */
    function transferWithoutFee(address sender, address recipient, uint256 amount) public onlyRole(OPERATORS) returns (bool) {
        require(recipient != address(0) && recipient != address(this));
        uint256 balance = balanceOf(sender);
        require(balance >= amount, "transferWithoutFee: transfer amount exceeds balance");
        _beforeTokenTransfer(sender, recipient, amount);
        _balances[sender] = balanceOf(sender).sub(amount, 'transferWithoutFee: transfer amount exceeds balance');
        _balances[recipient] = balanceOf(recipient).add(amount);
        emit Transfer(sender, recipient, amount);
        _afterTokenTransfer(sender, recipient, amount);
        return true;
    }

    function changeMaxSupply(uint224 max) public onlyRole(ADMINS) {
        maxSupply = max;
    }

    function changeTransferFee(uint256 _transferFee) public onlyRole(OPERATORS) {
        require(transferFee <= MAX_TRANSFER_FEE, "changeTransferFee: transferFee exceeds MAX_TRANSFER_FEE");
        transferFee = _transferFee;
    }

    function changeFeeAddress(address _feeAddress) public onlyRole(ADMINS) {
        feeAddress = _feeAddress;
    }

    function excludeFromFee(address account) public onlyRole(OPERATORS) {
        _isExcludedFromFee[account] = true;
    }

    function includeInFee(address account) public onlyRole(OPERATORS) {
        _isExcludedFromFee[account] = false;
    }
}