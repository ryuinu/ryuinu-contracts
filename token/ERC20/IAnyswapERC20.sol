// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Wrapped ERC-20 v10 (AnyswapERC20) is an ERC-20 ERC-20 wrapper. You can `deposit` ERC-20 and obtain an AnyswapERC20 balance which can then be operated as an ERC-20 token. You can
 *  `withdraw` ERC-20 from AnyswapERC20, which will then burn AnyswapERC20 token in your wallet. The amount of AnyswapERC20 token in any wallet is always identical to the
 * balance of ERC-20 deposited minus the ERC-20 withdrawn with that specific wallet.
 */
interface IAnyswapERC20 {

    /**
     * @dev Sets `value` as allowance of `spender` account over caller account's AnyswapERC20 token,
     * after which a call is executed to an ERC677-compliant contract with the `data` parameter.
     * Emits {Approval} event.
     * Returns boolean value indicating whether operation succeeded.
     * For more information on approveAndCall format, see https://github.com/ethereum/EIPs/issues/677.
     */
    function approveAndCall(address spender, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Moves `value` AnyswapERC20 token from caller's account to account (`to`),
     * after which a call is executed to an ERC677-compliant contract with the `data` parameter.
     * A transfer to `address(0)` triggers an ERC-20 withdraw matching the sent AnyswapERC20 token in favor of caller.
     * Emits {Transfer} event.
     * Returns boolean value indicating whether operation succeeded.
     * Requirements:
     *   - caller account must have at least `value` AnyswapERC20 token.
     * For more information on transferAndCall format, see https://github.com/ethereum/EIPs/issues/677.
     */
    function transferAndCall(address to, uint value, bytes calldata data) external returns (bool);

    function transferWithPermit(address target, address to, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external returns (bool);
}