// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.0;

import "./IAnyswapERC20.sol";
import "./ERC20.sol";
import "./IERC20.sol";
import "./IApprovalReceiver.sol";
import "./ITransferReceiver.sol";
import "./utils/SafeERC20.sol";
import "./../ERC20/extensions/IERC20Metadata.sol";
import "./../ERC20/extensions/IERC20Mintable.sol";
import "./../ERC20/extensions/IERC20Permit.sol";
import "../../utils/Context.sol";
import "../../utils/Counters.sol";
import "../../utils/cryptography/EIP712.sol";
import "../../utils/math/SafeMath.sol";

/**
 * @dev AnyswapERC20 is a modified version of https://github.com/connext/chaindata/blob/main/AnyswapV5ERC20.sol
 * modified to fit OpenZeppelin's contracts
 */

contract AnyswapERC20 is Context, EIP712, IERC20Mintable, IERC20Metadata, IERC20Permit, IAnyswapERC20 {
    using Counters for Counters.Counter;
    using SafeMath for uint256;
    using SafeERC20 for IERC20;
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    mapping(address => Counters.Counter) private _nonces;
    string public override name;
    string public override symbol;
    uint8  public immutable override decimals;
    address public immutable underlying;
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant TRANSFER_TYPEHASH = keccak256("Transfer(address owner,address to,uint256 value,uint256 nonce,uint256 deadline)");
    uint256 private _totalSupply;

    // init flag for setting immediate vault, needed for CREATE2 support
    bool private _init;

    // flag to enable/disable swapout vs vault.burn so multiple events are triggered
    bool private _vaultOnly;

    // configurable delay for timelock functions
    uint256 public delay = 2*24*3600;

    // set of minters, can be this bridge or other bridges
    mapping(address => bool) public isMinter;
    address[] public minters;

    // primary controller of the token contract
    address public vault;

    address public pendingMinter;
    uint256 public delayMinter;
    address public pendingVault;
    uint256 public delayVault;

    /**
     * @dev See {IERC20Permit-DOMAIN_SEPARATOR}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}
     */
    function balanceOf(address account) public override view returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner_, address spender) public override view returns (uint256) {
        return _allowances[owner_][spender];
    }

    modifier onlyAuth() virtual {
        require(isMinter[_msgSender()], "AnyswapERC20: FORBIDDEN");
        _;
    }

    modifier onlyVault() virtual {
        require(_msgSender() == mpc(), "AnyswapERC20: FORBIDDEN");
        _;
    }

    function owner() public view returns (address) {
        return mpc();
    }

    function mpc() public view returns (address) {
        if (block.timestamp >= delayVault) {
            return pendingVault;
        }
        return vault;
    }

    function setVaultOnly(bool enabled) external onlyVault {
        _vaultOnly = enabled;
    }

    function initVault(address _vault) external onlyVault {
        require(_init);
        vault = _vault;
        pendingVault = _vault;
        isMinter[_vault] = true;
        minters.push(_vault);
        delayVault = block.timestamp;
        _init = false;
    }

    function setMinter(address _auth) external onlyVault {
        pendingMinter = _auth;
        delayMinter = block.timestamp + delay;
    }

    function setVault(address _vault) external onlyVault {
        pendingVault = _vault;
        delayVault = block.timestamp + delay;
    }

    function applyVault() external onlyVault {
        require(block.timestamp >= delayVault);
        vault = pendingVault;
    }

    function applyMinter() external onlyVault {
        require(block.timestamp >= delayMinter);
        isMinter[pendingMinter] = true;
        minters.push(pendingMinter);
    }

    // No time delay revoke minter emergency function
    function revokeMinter(address _auth) external onlyVault {
        isMinter[_auth] = false;
    }

    function getAllMinters() external view returns (address[] memory) {
        return minters;
    }

    function changeVault(address newVault) external onlyVault returns (bool) {
        require(newVault != address(0), "AnyswapERC20: address(0x0)");
        pendingVault = newVault;
        delayVault = block.timestamp + delay;
        emit LogChangeVault(vault, pendingVault, delayVault);
        return true;
    }

    function changeMPCOwner(address newVault) public onlyVault returns (bool) {
        require(newVault != address(0), "AnyswapERC20: address(0x0)");
        pendingVault = newVault;
        delayVault = block.timestamp + delay;
        emit LogChangeMPCOwner(vault, pendingVault, delayVault);
        return true;
    }

    function mint(address to, uint256 amount) public virtual override onlyAuth returns (bool) {
        _mint(to, amount);
        return true;
    }

    function burn(address from, uint256 amount) public virtual onlyAuth returns (bool) {
        require(from != address(0), "AnyswapERC20: address(0x0)");
        _burn(from, amount);
        return true;
    }

    function Swapin(bytes32 txhash, address account, uint256 amount) public onlyAuth returns (bool) {
        _mint(account, amount);
        emit LogSwapin(txhash, account, amount);
        return true;
    }

    function Swapout(uint256 amount, address bindaddr) public returns (bool) {
        require(!_vaultOnly, "AnyswapERC20: onlyAuth");
        require(bindaddr != address(0), "AnyswapERC20: address(0x0)");
        _burn(_msgSender(), amount);
        emit LogSwapout(_msgSender(), bindaddr, amount);
        return true;
    }

    /**
     * @dev See {IERC20Permit-nonces}.
     * Records current ERC2612 nonce for account. This value must be included whenever signature is generated for {permit}.
     * Every successful call to {permit} increases account's nonce by one. This prevents signature from being used multiple times.
     */
    function nonces(address account) public view virtual override returns (uint256) {
        return _nonces[account].current();
    }

    event LogChangeVault(address indexed oldVault, address indexed newVault, uint256 indexed effectiveTime);
    event LogChangeMPCOwner(address indexed oldOwner, address indexed newOwner, uint256 indexed effectiveHeight);
    event LogSwapin(bytes32 indexed txhash, address indexed account, uint256 amount);
    event LogSwapout(address indexed account, address indexed bindaddr, uint256 amount);
    event LogAddAuth(address indexed auth, uint256 timestamp);

    constructor(string memory _name, string memory _symbol, uint8 _decimals, address _underlying, address _vault) EIP712(_name, "1") {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        underlying = _underlying;
        if (_underlying != address(0x0)) {
            require(_decimals == IERC20Metadata(_underlying).decimals());
        }

        // Use init to allow for CREATE2 across all chains
        _init = true;

        // Disable/Enable swapout for v1 tokens vs mint/burn for v3 tokens
        _vaultOnly = false;

        vault = _vault;
        pendingVault = _vault;
        delayVault = block.timestamp;

        uint256 chainId;
        assembly {chainId := chainid()}
    }

    function depositWithPermit(address target, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s, address to) external returns (uint256) {
        IERC20Permit(underlying).permit(target, address(this), value, deadline, v, r, s);
        IERC20(underlying).safeTransferFrom(target, address(this), value);
        return _deposit(value, to);
    }

    function depositWithTransferPermit(address target, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s, address to) external returns (uint256) {
        IAnyswapERC20(underlying).transferWithPermit(target, address(this), value, deadline, v, r, s);
        return _deposit(value, to);
    }

    function deposit() external returns (uint256) {
        uint256 _amount = IERC20(underlying).balanceOf(_msgSender());
        IERC20(underlying).safeTransferFrom(_msgSender(), address(this), _amount);
        return _deposit(_amount, _msgSender());
    }

    function deposit(uint256 amount) external returns (uint256) {
        IERC20(underlying).safeTransferFrom(_msgSender(), address(this), amount);
        return _deposit(amount, _msgSender());
    }

    function deposit(uint256 amount, address to) external returns (uint256) {
        IERC20(underlying).safeTransferFrom(_msgSender(), address(this), amount);
        return _deposit(amount, to);
    }

    function depositVault(uint256 amount, address to) external onlyVault returns (uint256) {
        return _deposit(amount, to);
    }

    function _deposit(uint256 amount, address to) internal returns (uint256) {
        require(underlying != address(0x0) && underlying != address(this));
        _mint(to, amount);
        return amount;
    }

    function withdraw() external returns (uint256) {
        return _withdraw(_msgSender(), balanceOf(_msgSender()), _msgSender());
    }

    function withdraw(uint256 amount) external returns (uint256) {
        return _withdraw(_msgSender(), amount, _msgSender());
    }

    function withdraw(uint256 amount, address to) external returns (uint256) {
        return _withdraw(_msgSender(), amount, to);
    }

    function withdrawVault(address from, uint256 amount, address to) external onlyVault returns (uint256) {
        return _withdraw(from, amount, to);
    }

    function _withdraw(address from, uint256 amount, address to) internal returns (uint256) {
        _burn(from, amount);
        IERC20(underlying).safeTransfer(to, amount);
        return amount;
    }

    /**
     * @dev Sets `value` as allowance of `spender` account over caller account's AnyswapERC20 token.
     * Emits {Approval} event.
     * Returns boolean value indicating whether operation succeeded.
     */
    function approve(address spender, uint256 value) external override returns (bool) {
        _approve(_msgSender(), spender, value);
        return true;
    }

    /**
     * @dev Sets `value` as allowance of `spender` account over caller account's AnyswapERC20 token,
     * after which a call is executed to an ERC677-compliant contract with the `data` parameter.
     * Emits {Approval} event.
     * Returns boolean value indicating whether operation succeeded.
     * For more information on approveAndCall format, see https://github.com/ethereum/EIPs/issues/677.
     */
    function approveAndCall(address spender, uint256 value, bytes calldata data) external override returns (bool) {
        _approve(_msgSender(), spender, value);
        return IApprovalReceiver(spender).onTokenApproval(_msgSender(), value, data);
    }

    /**
     * @dev Sets `value` as allowance of `spender` account over `owner` account's AnyswapERC20 token, given `owner` account's signed approval.
     * Emits {Approval} event.
     * Requirements:
     *   - `deadline` must be timestamp in future.
     *   - `v`, `r` and `s` must be valid `secp256k1` signature from `owner` account over EIP712-formatted function arguments.
     *   - the signature must use `owner` account's current nonce (see {nonces}).
     *   - the signer cannot be zero address and must be `owner` account.
     * For more information on signature format, see https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP section].
     * AnyswapERC20 token implementation adapted from https://github.com/albertocuestacanada/ERC20Permit/blob/master/contracts/ERC20Permit.sol.
     */
    function permit(address target, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external override {
        require(block.timestamp <= deadline, "AnyswapERC20: Expired permit");
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, target, spender, value, _useNonce(target), deadline));
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == target, "AnyswapERC20: invalid signature");

        _approve(target, spender, value);
    }

    function transferWithPermit(address target, address to, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external override returns (bool) {
        require(block.timestamp <= deadline, "AnyswapERC20: Expired permit");
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, target, to, value, _useNonce(target), deadline));
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == target, "AnyswapERC20: invalid signature");

        require(to != address(0) && to != address(this));
        _transfer(target, to, value);

        return true;
    }

    /**
     * @dev "Consume a nonce": return the current value and increment.
     */
    function _useNonce(address account) internal virtual returns (uint256 current) {
        Counters.Counter storage nonce = _nonces[account];
        current = nonce.current();
        nonce.increment();
    }

    /**
     * @dev Moves `value` AnyswapERC20 token from caller's account to account (`to`).
     * A transfer to `address(0)` triggers an ETH withdraw matching the sent AnyswapERC20 token in favor of caller.
     * Emits {Transfer} event.
     * Returns boolean value indicating whether operation succeeded.
     * Requirements:
     *   - caller account must have at least `value` AnyswapERC20 token.
     */
    function transfer(address to, uint256 value) external virtual override returns (bool) {
        require(to != address(0) && to != address(this));
        _transfer(_msgSender(), to, value);
        return true;
    }

    /**
     * @dev Moves `value` AnyswapERC20 token from account (`from`) to account (`to`) using allowance mechanism.
     * `value` is then deducted from caller account's allowance, unless set to `type(uint256).max`.
     * A transfer to `address(0)` triggers an ETH withdraw matching the sent AnyswapERC20 token in favor of caller.
     * Emits {Approval} event to reflect reduced allowance `value` for caller account to spend from account (`from`),
     * unless allowance is set to `type(uint256).max`
     * Emits {Transfer} event.
     * Returns boolean value indicating whether operation succeeded.
     * Requirements:
     *   - `from` account must have at least `value` balance of AnyswapERC20 token.
     *   - `from` account must have approved caller to spend at least `value` of AnyswapERC20 token, unless `from` and caller are the same account.
     */
    function transferFrom(address from, address to, uint256 value) external override returns (bool) {
        require(to != address(0) && to != address(this));
        if (from != _msgSender()) {
            uint256 allowed = allowance(from, _msgSender());
            if (allowed != type(uint256).max) {
                require(allowed >= value, "AnyswapERC20: request exceeds allowance");
                uint256 reduced = allowed - value;
                _approve(from, _msgSender(), reduced);
            }
        }

        _transfer(from, to, value);
        return true;
    }

    /**
     * @dev Moves `value` AnyswapERC20 token from caller's account to account (`to`),
     * after which a call is executed to an ERC677-compliant contract with the `data` parameter.
     * A transfer to `address(0)` triggers an ETH withdraw matching the sent AnyswapERC20 token in favor of caller.
     * Emits {Transfer} event.
     * Returns boolean value indicating whether operation succeeded.
     * Requirements:
     *   - caller account must have at least `value` AnyswapERC20 token.
     * For more information on transferAndCall format, see https://github.com/ethereum/EIPs/issues/677.
     */
    function transferAndCall(address to, uint256 value, bytes calldata data) external override returns (bool) {
        require(to != address(0) && to != address(this));
        _transfer(_msgSender(), to, value);
        return ITransferReceiver(to).onTokenTransfer(_msgSender(), value, data);
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, 'AnyswapERC20: decreased allowance below zero'));
        return true;
    }

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        uint256 balance = balanceOf(sender);
        require(balance >= amount, "AnyswapERC20: transfer amount exceeds balance");

        _beforeTokenTransfer(sender, recipient, amount);

        _balances[sender] = balanceOf(sender).sub(amount, 'AnyswapERC20: transfer amount exceeds balance');
        _balances[recipient] = balanceOf(recipient).add(amount);
        emit Transfer(sender, recipient, amount);

        _afterTokenTransfer(sender, recipient, amount);
    }

    /**
     * @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements
     *
     * - `account` cannot be the zero address.
     */
    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), 'AnyswapERC20: mint to the zero address');

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = balanceOf(account).add(amount);
        emit Transfer(address(0), account, amount);

        _afterTokenTransfer(address(0), account, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the
     * total supply.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * Requirements
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     */
    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), 'AnyswapERC20: burn from the zero address');

        _beforeTokenTransfer(account, address(0), amount);

        _balances[account] = balanceOf(account).sub(amount);
        _totalSupply = _totalSupply.sub(amount, 'AnyswapERC20: burn amount exceeds balance');
        emit Transfer(account, address(0), amount);

        _afterTokenTransfer(account, address(0), amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner_`s tokens.
     *
     * This is internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     */
    function _approve(address account, address spender, uint256 amount) internal {
        _allowances[account][spender] = amount;
        emit Approval(account, spender, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`.`amount` is then deducted
     * from the caller's allowance.
     *
     * See {_burn} and {_approve}.
     */
    function _burnFrom(address account, uint256 amount) internal {
        _burn(account, amount);
        _approve(account, _msgSender(), _allowances[account][_msgSender()].sub(amount, 'AnyswapERC20: burn amount exceeds allowance'));
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual {}

    /**
     * @dev Hook that is called after any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * has been transferred to `to`.
     * - when `from` is zero, `amount` tokens have been minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens have been burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _afterTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual {}
}