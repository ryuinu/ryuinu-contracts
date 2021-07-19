// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./access/RoleAccessControl.sol";
import "./security/ReentrancyGuard.sol";
import "./token/ERC20/IERC20.sol";
import "./token/ERC20/extensions/IERC20Mintable.sol";
import "./token/ERC20/utils/SafeERC20.sol";
import "./utils/math/SafeMath.sol";
import "./IReferral.sol";

contract MasterChef is RoleAccessControl, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Info of each user.
    struct UserInfo {
        uint256 amount;         // How many LP tokens the user has provided.
        uint256 rewardDebt;     // Reward debt. See explanation below.
        //
        // We do some fancy math here. Basically, any point in time, the amount of FarmTokens
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accFarmTokenPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accFarmTokenPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 lpToken;                 // Address of LP token contract.
        uint256 allocPoint;             // How many allocation points assigned to this pool. FarmTokens to distribute per block.
        uint256 lastRewardBlock;        // Last block number that FarmTokens distribution occurs.
        uint256 accFarmTokenPerShare;   // Accumulated FarmTokens per share, times 1e12. See below.
        uint16 depositFeeBP;            // Deposit fee in basis points
    }

    // The FarmToken!
    IERC20Mintable public farmToken;
    // Dev address
    address public devAddress;
    // Deposit fee address
    address public feeAddress;
    // Max supply
    uint224 public maxSupply = type(uint224).max;
    // FarmTokens created per block.
    uint256 public farmTokenPerBlock = 10000 ether;
    // The block number when FarmToken mining starts.
    uint256 public startBlock;
    // Bonus multiplier for early FarmToken makers.
    uint256 public BONUS_MULTIPLIER = 1;

    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    // Pool Exists Mapper
    mapping(IERC20 => bool) public poolExistence;
    // Pool ID Tracker Mapper
    mapping(IERC20 => uint256) public poolIdForLpAddress;
    // Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;

    IReferral public referral;
    // Referral Bonus in basis points. Initially set to 2%
    uint16 public refBonusBP = 200;
    // Max deposit fee: 10%.
    uint16 public constant MAXIMUM_DEPOSIT_FEE_BP = 1000;
    // Max referral commission rate: 5%.
    uint16 public constant MAXIMUM_REFERRAL_BP = 500;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event SetFeeAddress(address indexed user, address indexed newAddress);
    event SetDevAddress(address indexed user, address indexed newAddress);
    event SetReferralAddress(address indexed user, IReferral indexed newAddress);
    event ReferralPaid(address indexed user, address indexed userTo, uint256 reward);
    event ReferralBonusBpChanged(uint256 oldBp, uint256 newBp);
    event UpdateEmissionRate(address indexed user, uint256 farmTokenPerBlock);
    event UpdateMaxSupply(address indexed user, uint224 maxSupply);

    constructor(
        IERC20Mintable _farmToken,
        address _devAddress,
        address _feeAddress,
        uint256 _startBlock
    ) {
        farmToken = _farmToken;
        devAddress = _devAddress;
        feeAddress = _feeAddress;
        startBlock = _startBlock;
        _setupRole(ADMINS, _msgSender());
    }

    modifier nonDuplicated(IERC20 _lpToken) {
        require(poolExistence[_lpToken] == false, "nonDuplicated: duplicated");
        _;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    function getPoolIdForLpToken(IERC20 _lpToken) external view returns (uint256) {
        require(poolExistence[_lpToken] != false, "getPoolIdForLpToken: do not exist");
        return poolIdForLpAddress[_lpToken];
    }

    // Add a new lp to the pool. Can only be called by the owner.
    // DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    function add(uint256 _allocPoint, IERC20 _lpToken, uint16 _depositFeeBP, bool _withUpdate) public onlyRole(OPERATORS) nonDuplicated(_lpToken) {
        require(_depositFeeBP <= MAXIMUM_DEPOSIT_FEE_BP, "add: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolExistence[_lpToken] = true;
        poolInfo.push(
            PoolInfo({
              lpToken : _lpToken,
              allocPoint : _allocPoint,
              lastRewardBlock : lastRewardBlock,
              accFarmTokenPerShare : 0,
              depositFeeBP : _depositFeeBP
          })
        );
        poolIdForLpAddress[_lpToken] = poolInfo.length - 1;
    }

    // Update the given pool's FarmToken allocation point and deposit fee. Can only be called by the owner.
    function set(uint256 _pid, uint256 _allocPoint, uint16 _depositFeeBP, bool _withUpdate) public onlyRole(OPERATORS) {
        require(_depositFeeBP <= MAXIMUM_DEPOSIT_FEE_BP, "set: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
    }

    function updateMultiplier(uint256 multiplierNumber) public onlyRole(OPERATORS) {
        BONUS_MULTIPLIER = multiplierNumber;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
        if (farmToken.totalSupply()  >= maxSupply) {
            return 0;
        }
        return _to.sub(_from).mul(BONUS_MULTIPLIER);
    }

    // View function to see pending FarmTokens on frontend.
    function pendingFarmToken(uint256 _pid, address _user) external view returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accFarmTokenPerShare = pool.accFarmTokenPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 farmTokenReward = multiplier.mul(farmTokenPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
            accFarmTokenPerShare = accFarmTokenPerShare.add(farmTokenReward.mul(1e12).div(lpSupply));
        }
        return user.amount.mul(accFarmTokenPerShare).div(1e12).sub(user.rewardDebt);
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0 || pool.allocPoint == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 farmTokenReward = multiplier.mul(farmTokenPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
        // farmToken.mint(devAddress, farmTokenReward.div(10));
        // farmToken.mint(address(this), farmTokenReward);
        pool.accFarmTokenPerShare = pool.accFarmTokenPerShare.add(farmTokenReward.mul(1e12).div(lpSupply));
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to MasterChef for FarmToken allocation.
    function deposit(uint256 _pid, uint256 _amount, address _referrer) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];
        updatePool(_pid);
        if (_amount > 0 && address(referral) != address(0) && _referrer != address(0) && _referrer != _msgSender()) {
            referral.recordReferral(_msgSender(), _referrer);
        }
        // withdraw FarmToken rewards
        if (user.amount > 0) {
            uint256 pending = user.amount.mul(pool.accFarmTokenPerShare).div(1e12).sub(user.rewardDebt);
            if (pending > 0) {
                safeFarmTokenTransfer(_msgSender(), pending);
                payReferralCommission(_msgSender(), pending);
            }
        }
        // deposit lp token
        if (_amount > 0) {
            pool.lpToken.safeTransferFrom(address(_msgSender()), address(this), _amount);
            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                pool.lpToken.safeTransfer(feeAddress, depositFee);
                user.amount = user.amount.add(_amount).sub(depositFee);
            } else {
                user.amount = user.amount.add(_amount);
            }
        }
        user.rewardDebt = user.amount.mul(pool.accFarmTokenPerShare).div(1e12);
        emit Deposit(_msgSender(), _pid, _amount);
    }

    // Withdraw LP tokens from MasterChef
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        // withdraw FarmToken rewards
        uint256 pending = user.amount.mul(pool.accFarmTokenPerShare).div(1e12).sub(user.rewardDebt);
        if (pending > 0) {
            safeFarmTokenTransfer(_msgSender(), pending);
            payReferralCommission(_msgSender(), pending);
        }
        // withdraw lp token
        if (_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(_msgSender()), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accFarmTokenPerShare).div(1e12);
        emit Withdraw(_msgSender(), _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_msgSender()];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        pool.lpToken.safeTransfer(address(_msgSender()), amount);
        emit EmergencyWithdraw(_msgSender(), _pid, amount);
    }

    // Safe FarmToken transfer function, just in case if rounding error causes pool to not have enough FarmTokens.
    function safeFarmTokenTransfer(address _to, uint256 _amount) internal {
        uint256 farmTokenBal = farmToken.balanceOf(address(this));
        bool transferSuccess = false;
        if (_amount > farmTokenBal) {
            transferSuccess = farmToken.transfer(_to, farmTokenBal);
        } else {
            transferSuccess = farmToken.transfer(_to, _amount);
        }
        require(transferSuccess, "safeFarmTokenTransfer: transfer failed");
    }

    function setDevAddress(address _devAddress) public onlyRole(ADMINS) {
        require(_devAddress != address(0), "setDevAddress: invalid address");
        devAddress = _devAddress;
        emit SetDevAddress(_msgSender(), _devAddress);
    }

    function setFeeAddress(address _feeAddress) public onlyRole(ADMINS) {
        require(_feeAddress != address(0), "setFeeAddress: invalid address");
        feeAddress = _feeAddress;
        emit SetFeeAddress(_msgSender(), _feeAddress);
    }

    function updateEmissionRate(uint256 _farmTokenPerBlock, bool _withUpdate) public onlyRole(OPERATORS) {
        // Added to give option of mass update
        if(_withUpdate) {
            massUpdatePools();
        }
        farmTokenPerBlock = _farmTokenPerBlock;
        emit UpdateEmissionRate(_msgSender(), _farmTokenPerBlock);
    }

    function updateMaxSupply(uint224 _maxSupply) external onlyRole(OPERATORS) {
        maxSupply = _maxSupply;
        emit UpdateMaxSupply(_msgSender(), _maxSupply);
    }

    // Update the referral contract address
    function setReferralAddress(IReferral _referral) external onlyRole(OPERATORS) {
        referral = _referral;
        emit SetReferralAddress(_msgSender(), _referral);
    }

    /**
     * @dev Referral Bonus in basis points.
     */
    function updateReferralBonusBp(uint16 _newRefBonusBp) public onlyRole(OPERATORS) {
        require(_newRefBonusBp <= MAXIMUM_REFERRAL_BP, "updateRefBonusPercent: invalid referral bonus basis points");
        require(_newRefBonusBp != refBonusBP, "updateRefBonusPercent: same bonus bp set");
        uint256 previousRefBonusBP = refBonusBP;
        refBonusBP = _newRefBonusBp;
        emit ReferralBonusBpChanged(previousRefBonusBP, _newRefBonusBp);
    }

    /**
     * @dev Pay referral commission to the referrer who referred this user.
     */
    function payReferralCommission(address _user, uint256 _pending) internal {
        if (address(referral) != address(0) && refBonusBP > 0) {
            address referrer = referral.getReferrer(_user);
            if (referrer != address(0) && referrer != _user) {
                uint256 refBonusEarned = _pending.mul(refBonusBP).div(10000);
                // farmToken.mint(referrer, refBonusEarned);
                safeFarmTokenTransfer(referrer, refBonusEarned);
                emit ReferralPaid(_user, referrer, refBonusEarned);
            }
        }
    }

    // Only update before start of farm
    function updateStartBlock(uint256 _startBlock) public onlyRole(ADMINS) {
        startBlock = _startBlock;
    }

    // Migrate farmTokens if there is need to update this contract or if there is decision to burn supply within contract
    function migrateFarmToken(address _to, uint256 _amount) public onlyRole(ADMINS) {
        require(_amount > 0, "migrateFarmToken: invalid amount");
        safeFarmTokenTransfer(_to, _amount);
    }
}