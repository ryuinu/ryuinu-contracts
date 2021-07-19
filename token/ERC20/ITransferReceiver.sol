// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface ITransferReceiver {
    function onTokenTransfer(address, uint, bytes calldata) external returns (bool);
}