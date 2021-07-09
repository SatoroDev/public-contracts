// SPDX-License-Identifier: MIT
/**
DAPP:  https://dapp.satoroswap.finance
DEX:       https://satoroswap.finance
TG:       https://t.me/satoroswapn
*/

pragma solidity 0.6.12;


import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../token/SATORO.sol";



// SATOROFarming is the master of SATORO. He can make SATORO and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once SATORO is sufficiently
// distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.

interface Boosting {

    function deposit(uint pid, address user, uint lockTime, uint tokenId) external;

    function withdraw(uint pid, address user) external;

    function checkWithdraw(uint pid, address user) external view returns (bool);

    function getMultiplier(uint pid, address user) external view returns (uint); // satorom in 1e12 times;

}

contract SATOROFarming is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Info of each user.
    struct UserInfo {
        uint256 amount;     // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.

        // We do some fancy math here. Basically, any point in time, the amount of SATOROs
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accSATOROPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accSATOROPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 lpToken;           // Address of LP token contract.
        uint256 allocPoint;       // How many allocation points assigned to this pool. SATOROs to distribute per block.
        uint256 lastRewardBlock;  // Last block number that SATOROs distribution occurs.
        uint256 accSATOROPerShare;   // Accumulated SATOROs per share, times 1e12. See below.
        uint256 depositFeeBP;      // Deposit fees
        address boostAddr;      // boostAddr
        bool emergencyMode;
    }

    // The SATORO TOKEN!
    SATORO public satoro;
    // Dev address.
    address public devaddr;

    // Fees Addr
    address public feeAddress;
    // The block number when SATORO mining starts.
    uint256 public startBlock;
    // Block number when SATORO period ends.
    uint256 public allEndBlock;
    // SATORO tokens created per block.
    uint256 public satoroPerBlock;
    // Max multiplier
    uint256 public maxMultiplier;

    // Referral Bonus in basis points. Initially set to 3%
    uint256 public refBonusBP = 300;
    // Max referral commission rate: 20%.
    uint256 public constant MAXIMUM_REFERRAL_BP = 2000;

    uint256 public constant MAXIMUM_DEPOSIT_FEE_BP = 1000;
    // Referral Mapping
    mapping(address => address) public referrers; // account_address -> referrer_address
    mapping(address => uint256) public referredCount; // referrer_address -> num_of_referred

    //deposit Fees whitelist
    mapping(address => bool) public whitelist;

    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping (uint256 => mapping (address => UserInfo)) public userInfo;
    // Total allocation poitns. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;


    uint256 public constant TEAM_PERCENT = 23; 

    uint256 public constant PID_NOT_SET = 0xffffffff; 


    event Deposit(address indexed user, uint256 indexed pid, uint256 amount, address _referrer);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);

    event Referral(address indexed _referrer, address indexed _user);
    event ReferralPaid(address indexed _user, address indexed _userTo, uint256 _reward);
    event ReferralBonusBpChanged(uint256 _oldBp, uint256 _newBp);

    constructor(
        SATORO _satoro,
        address _devaddr,
        uint256 _satoroPerBlock,
        uint256 _startBlock,
        uint256 _allEndBlock
    ) public {
        satoro = _satoro;
        devaddr = _devaddr;
        feeAddress= _devaddr;
        startBlock = _startBlock;
        allEndBlock = _allEndBlock;
        satoroPerBlock = _satoroPerBlock;
        maxMultiplier = 3e12;
    }

    function setMaxMultiplier(uint _maxMultiplier) public onlyOwner {
        maxMultiplier = _maxMultiplier;
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    function add(uint256 _allocPoint, IERC20 _lpToken, bool _withUpdate, uint256 _depositFeeBP, address _boostAddr) public onlyOwner {
        require(_depositFeeBP <= MAXIMUM_DEPOSIT_FEE_BP, "add: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);

        poolInfo.push(PoolInfo({
            lpToken: _lpToken,
            allocPoint: _allocPoint,
            lastRewardBlock: lastRewardBlock,
            accSATOROPerShare: 0,
            depositFeeBP: _depositFeeBP,
            boostAddr: _boostAddr,
            emergencyMode: false
        }));
    }

    // Update the given pool's SATORO allocation point. Can only be called by the owner.
    function set(uint256 _pid, uint256 _allocPoint, bool _withUpdate, uint256 _depositFeeBP, address _boostAddr) public onlyOwner {
        require(_depositFeeBP <= MAXIMUM_DEPOSIT_FEE_BP, "set: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
        poolInfo[_pid].boostAddr = _boostAddr;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
        if (_from >= allEndBlock) {
            return 0;
        }

        if (_to < startBlock) {
            return 0;
        }

        if (_to > allEndBlock && _from < startBlock) {
            return allEndBlock.sub(startBlock);
        }

        if (_to > allEndBlock) {
            return allEndBlock.sub(_from);
        }

        if (_from < startBlock) {
            return _to.sub(startBlock);
        }

        return _to.sub(_from);
    }

    // View function to see pending SATOROs on frontend.
    function pendingSATORO(uint256 _pid, address _user) external view returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accSATOROPerShare = pool.accSATOROPerShare;
        
        uint256 lpSupply;
        lpSupply = pool.lpToken.balanceOf(address(this));

        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 satoroReward = multiplier.mul(satoroPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
            accSATOROPerShare = accSATOROPerShare.add(satoroReward.mul(1e12).div(lpSupply));
            // multiplier from lockTime and NFT
            if (pool.boostAddr != address(0)) {
                uint multiplier2 = Boosting(pool.boostAddr).getMultiplier(_pid, _user);
                if (multiplier2 > maxMultiplier) {
                    multiplier2 = maxMultiplier;
                }
                return user.amount.mul(accSATOROPerShare).div(1e12).sub(user.rewardDebt).mul(multiplier2).div(1e12);
            }
        }
        return user.amount.mul(accSATOROPerShare).div(1e12).sub(user.rewardDebt);
    }

    // Update reward vairables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        
        uint256 lpSupply;
        lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0) {
            if (pool.lastRewardBlock < block.number) {
                pool.lastRewardBlock = block.number;
            }
            return;
        }
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 satoroReward = multiplier.mul(satoroPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
        pool.accSATOROPerShare = pool.accSATOROPerShare.add(satoroReward.mul(1e12).div(lpSupply));
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to SATOROFarming for SATORO allocation.
    function deposit(uint256 _pid, uint256 _amount, uint lockTime, uint nftTokenId,  address _referrer) public nonReentrant{
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);

        if (_amount > 0 && _referrer != address(0) && _referrer == address(_referrer) && _referrer != msg.sender) {
            setReferral(msg.sender, _referrer);
        }		

        if (user.amount > 0) {
            uint256 pending = user.amount.mul(pool.accSATOROPerShare).div(1e12).sub(user.rewardDebt);
            if (pool.boostAddr != address(0)) {
                // multiplier from lockTime and NFT
                uint multiplier2 = Boosting(pool.boostAddr).getMultiplier(_pid, msg.sender);
                if (multiplier2 > maxMultiplier) {
                    multiplier2 = maxMultiplier;
                }
                pending = pending.mul(multiplier2).div(1e12);
            }

            pending = mintSATORO(pending);
            safeSATOROTransfer(msg.sender, pending);
            }

            if( _amount >0){
                pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
                if (pool.boostAddr != address(0)) {
                    Boosting(pool.boostAddr).deposit(_pid, msg.sender, lockTime, nftTokenId);
                    }
                if ( pool.depositFeeBP >0 && !whitelist[msg.sender]){
                    uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                    user.amount = user.amount.add(_amount).sub(depositFee);
                    pool.lpToken.safeTransfer(feeAddress, depositFee); 
                }
                else{
                    user.amount = user.amount.add(_amount);
                }
            }

        user.rewardDebt = user.amount.mul(pool.accSATOROPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _amount, _referrer);
    }

    // Withdraw LP tokens from SATOROFarming.
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant{
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        uint256 pending = user.amount.mul(pool.accSATOROPerShare).div(1e12).sub(user.rewardDebt);
        if (pool.boostAddr != address(0)) {
            // multiplier from lockTime and NFT
            uint multiplier2 = Boosting(pool.boostAddr).getMultiplier(_pid, msg.sender);
            if (multiplier2 > maxMultiplier) {
                multiplier2 = maxMultiplier;
            }
            pending = pending.mul(multiplier2).div(1e12);
        }

        user.amount = user.amount.sub(_amount);
        user.rewardDebt = user.amount.mul(pool.accSATOROPerShare).div(1e12);

        pending = mintSATORO(pending);
        safeSATOROTransfer(msg.sender, pending);

        if (_amount > 0) {
            if (pool.boostAddr != address(0)) {
                require(Boosting(pool.boostAddr).checkWithdraw(_pid, msg.sender), "Lock time not finish");
                if (user.amount == 0x0) {
                    Boosting(pool.boostAddr).withdraw(_pid, msg.sender);
                }
            }

            pool.lpToken.safeTransfer(address(msg.sender), _amount);
        }

        emit Withdraw(msg.sender, _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdrawEnable(uint256 _pid) public onlyOwner {
        PoolInfo storage pool = poolInfo[_pid];
        pool.emergencyMode = true;
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant{
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.emergencyMode, "not enable emergence mode");

        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        pool.lpToken.safeTransfer(address(msg.sender), amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }

    // Safe satoro transfer function, just in case if rounding error causes pool to not have enough SATOROs.
    function safeSATOROTransfer(address _to, uint256 _amount) internal {
        uint256 satoroBal = satoro.balanceOf(address(this));
        if (_amount > satoroBal) {
            satoro.transfer(_to, satoroBal);
        } else {
            satoro.transfer(_to, _amount);
        }
    }


    // Update dev address by the previous dev.
    function dev(address _devaddr) public onlyOwner {
        devaddr = _devaddr;
    }

    // Update fee address by the previous fee address.
    function setFeeAddress(address _feeAddress) public onlyOwner{
        feeAddress = _feeAddress;
    }

    // Update whitelist address 
    function setWhitelist(address _address) public onlyOwner{
        whitelist[_address] = true;
    }


    function mintSATORO(uint amount) private returns (uint ){
        satoro.mint(devaddr, amount.mul(TEAM_PERCENT).div(100));
        uint refer = payReferralCommission(msg.sender, amount);
        uint pending = amount.sub(refer);
        satoro.mint(address(this), pending);
        return pending;
    }

   // Set Referral Address for a user
    function setReferral(address _user, address _referrer) internal {
        if (_referrer == address(_referrer) && referrers[_user] == address(0) && _referrer != address(0) && _referrer != _user) {
            referrers[_user] = _referrer;
            referredCount[_referrer] += 1;
            emit Referral(_user, _referrer);
            }
    }

    // Get Referral Address for a Account
    function getReferral(address _user) public view returns (address) {
        return referrers[_user];
    }

    function isReferral(address _user) internal view returns (bool){
       address referrer = getReferral(_user);
       if (referrer != address(0) && referrer != _user && refBonusBP > 0) {
            return true;
       }
       else{
            return false;
       }
    }

    // Pay referral commission to the referrer who referred this user.
    function payReferralCommission(address _user, uint256 _pending) internal returns (uint){
        address referrer = getReferral(_user);
        if (isReferral(_user)){
            uint256 refBonusEarned = _pending.mul(refBonusBP).div(10000);
            satoro.mint(referrer, refBonusEarned);
            emit ReferralPaid(_user, referrer, refBonusEarned);
            return refBonusEarned;
        }
        return 0;
    }

    // Initially set to 3%, this this the ability to increase or decrease the Bonus percentage based on
    // community voting and feedback.
    function updateReferralBonusBp(uint256 _newRefBonusBp) public onlyOwner {
        require(_newRefBonusBp <= MAXIMUM_REFERRAL_BP, "updateRefBonusPercent: invalid referral bonus basis points");
        require(_newRefBonusBp != refBonusBP, "updateRefBonusPercent: same bonus bp set");
        uint256 previousRefBonusBP = refBonusBP;
        refBonusBP = _newRefBonusBp;
        emit ReferralBonusBpChanged(previousRefBonusBP, _newRefBonusBp);
    }

}
