// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IApprovalReceiver {
    function onTokenApproval(address, uint, bytes calldata) external returns (bool);
}