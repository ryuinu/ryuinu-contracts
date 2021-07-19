// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../utils/Context.sol";
import "../utils/Strings.sol";

interface IRoleAccessControl {
  function hasRole(uint32 role, address account) external view returns (bool);
  function grantRole(uint32 role, address account) external;
  function revokeRole(uint32 role, address account) external;
  function renounceRole(uint32 role, address account) external;
}

/**
 * @dev Access is based on hierarchy of power
 * ADMINS can manage OPERATORS but OPERATORS cannot manage ADMINS
 */
abstract contract RoleAccessControl is Context, IRoleAccessControl, ERC165 {
  // Guests have no privileges
  uint32 public constant GUESTS = 0;
  // Operators can manage the contracts
  uint32 public constant OPERATORS = 100;
  // Admins can manage operators
  uint32 public constant ADMINS = 1000;
  event RoleGranted(uint32 indexed role, address indexed account, address indexed sender);
  event RoleRevoked(uint32 indexed role, address indexed account, address indexed send);

  struct Member {
    address account;
    uint32 id;
    uint32 role;
  }
  Member[] private _members;

  // Keep track of every address and their role
  mapping (address => uint32) internal _addressToMemberId;

  /**
   * @dev See {IERC165-supportsInterface}.
   */
  function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
    return interfaceId == type(IRoleAccessControl).interfaceId
    || super.supportsInterface(interfaceId);
  }

  /**
   * @dev Modifier that checks that an account has a specific role. Reverts
   * with a standardized message including the required role.
   */
  modifier onlyRole(uint32 role) {
    if(!hasRole(role,  _msgSender())) {
      revert(string(abi.encodePacked(
          "RoleAccessControl: account ",
          Strings.toHexString(uint160(_msgSender()), 20),
          " is missing role ",
          Strings.toHexString(uint256(role), 32)
        )));
    }
    _;
  }

  /**
   * @dev Returns `true` if `account` has been granted `role`. or above
   */
  function hasRole(uint32 role, address _address) public view override returns(bool) {
    uint32 id = _addressToMemberId[_address];
    if(_members[id].role >= role) return true;
    return false;
  }

  // Only called once at constructor
  function _setupRole(uint32 _role, address _address) internal virtual {
    _members.push(Member(_address, 0, _role));
  }

  // Add a new member without any privileges
  function _addMember(address _address) private {
    // check if doesn't exist
    uint32 id = _addressToMemberId[_address];
    if(_members[id].account != _address) {
      // add member without giving any roles
      _addressToMemberId[_address] = uint32(_members.length);
      _members.push(Member(_address, uint32(_members.length), GUESTS));
    }
  }

  function grantRole(uint32 _role, address _address) public virtual override onlyRole(OPERATORS) {
    _grantRole(_role, _address);
  }

  // Need to add member first before adding role
  function _grantRole(uint32 _role, address _address) internal {
    _addMember(_address);
    uint32 id = _addressToMemberId[_address];
    require(!hasRole(_role, _address), string(abi.encodePacked(Strings.toHexString(uint160(_members[id].account), 20), " has role ", Strings.toHexString(uint32(_role)))));

    // grant if role <= sender _role
    uint32 senderId = _addressToMemberId[_msgSender()];
    require(_role <= _members[senderId].role, string(abi.encodePacked(Strings.toHexString(uint160(_members[senderId].account), 20), " is below role ", Strings.toHexString(uint32(_role)))));

    _members[id].role = _role;
    emit RoleGranted(_role, _members[id].account, _msgSender());
  }

  // Create new array of roles and assign to member
  function revokeRole(uint32 _role, address _address) public virtual override onlyRole(OPERATORS) {
    _revokeRole(_role, _address);
  }

  // Anyone can revoke their own role
  function renounceRole(uint32 _role, address _address) public virtual override {
    require(_address == _msgSender(), string(abi.encodePacked(Strings.toHexString(uint160(_address), 20), " is not sender")));
    _revokeRole(_role, _address);
  }

  function _revokeRole(uint32 _role, address _address) internal {
    uint32 id = _addressToMemberId[_address];
    require(hasRole(_role, _address), string(abi.encodePacked(Strings.toHexString(uint160(_members[id].account), 20), " is missing role ", Strings.toHexString(uint32(_role)))));

    // revoke if role <= sender _role
    uint32 senderId = _addressToMemberId[_msgSender()];
    require(_role <= _members[senderId].role, string(abi.encodePacked(Strings.toHexString(uint160(_members[senderId].account), 20), " is below role ", Strings.toHexString(uint32(_role)))));

    _members[id].role = GUESTS;
    emit RoleRevoked(_role, _members[id].account, _msgSender());
  }

  /**
   * @dev Get all members info
   */
  function getAllMembers() public view returns(string memory) {
    string memory s = '{';
    for(uint32 i = 0; i < uint32(_members.length); i++) {
      s = string(abi.encodePacked(
        s,
        "{ address: ",
        Strings.toHexString(uint160(_members[i].account)),
        ", id: ",
        Strings.toHexString(_members[i].id),
        ", role: ",
        Strings.toHexString(_members[i].role),
        " }, "
      ));
    }
    s = string(abi.encodePacked(s, '}'));
    return s;
  }
}
