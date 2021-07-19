// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./token/ERC20/utils/SafeERC20.sol";
import "./access/RoleAccessControl.sol";
import "./IReferral.sol";

contract Referral is IReferral, RoleAccessControl {
    using SafeERC20 for IERC20;

    mapping(address => address) public referrers; // user address => referrer address
    mapping(address => uint256) public referralsCount; // referrer address => referrals count

    event ReferralRecorded(address indexed user, address indexed referrer);
    event ReferralAdded(address indexed user, address indexed referrer);
    event ReferralRemoved(address indexed user, address indexed referrer);

    constructor() {
        _setupRole(ADMINS, _msgSender());
    }

    // Set Referral Address for a user
    function recordReferral(address _user, address _referrer) public override onlyRole(OPERATORS) {
        if (_referrer == address(_referrer)
            && _user != address(0)
            && referrers[_user] == address(0)
            && _referrer != address(0)
            && _referrer != _user) {
            referrers[_user] = _referrer;
            referralsCount[_referrer] += 1;
            emit ReferralRecorded(_user, _referrer);
        }
    }

    // Manually add Referral Address for a user
    function addReferral(address _user, address _referrer) public onlyRole(OPERATORS) {
        if (_referrer == address(_referrer)
        && _user != address(0)
        && referrers[_user] == address(0)
        && _referrer != address(0)
            && _referrer != _user) {
            referrers[_user] = _referrer;
            referralsCount[_referrer] += 1;
            emit ReferralAdded(_user, _referrer);
        }
    }

    // Manually remove Referral Address for a user
    function removeReferral(address _user, address _referrer) public onlyRole(OPERATORS) {
        if (_referrer == address(_referrer)
        && _user != address(0)
        && referrers[_user] == address(0)
        && _referrer != address(0)
            && _referrer != _user) {
            delete referrers[_user];
            referralsCount[_referrer] -= 1;
            emit ReferralRemoved(_user, _referrer);
        }
    }

    // Get the referrer address that referred the user
    function getReferrer(address _user) public override view returns (address) {
        return referrers[_user];
    }

    // Transfer tokens that are sent here by mistake
    function transferToken(IERC20 _token, uint256 _amount, address _to) external onlyRole(OPERATORS) {
        _token.safeTransfer(_to, _amount);
    }
}