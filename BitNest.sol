// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./IPositionManager.sol";
import "./UniswapUtil.sol";

// Main contract for BitNest, handling liquidity operations and access control
contract BitNest is Initializable, AccessControlUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE"); // Role for operators
    address public constant USDT = 0x55d398326f99059fF775485246999027B3197955; // USDT token address
    address public constant FUEL = 0x4b1f4fAd5E9711ADb0018ff0b56c758D63e43478; // FUEL token address
    IPositionManager public constant PositionManager = IPositionManager(0x46A15B0b27311cedF172AB29E4f4766fbE7F4364); // Position manager contract
    address private fuelReceiver; // Address to receive FUEL tokens
    mapping(address => bool) public signers; // Authorized signers
    mapping(bytes32 => bool) public nonces; // Used nonces for transactions
    mapping(uint256 => bool) public orderIds; // Order IDs to prevent duplicates
    mapping(uint256 => bool) public circulateIds; // Circulation IDs to prevent duplicates
    uint256 private receiveTokenId; // Token ID for receiving liquidity
    uint256 private withdrawTokenId; // Token ID for withdrawing liquidity
    uint160 private tickLowerSqrtRatio; // Lower tick square root ratio for liquidity calculations
    uint160 private tickUpperSqrtRatio; // Upper tick square root ratio for liquidity calculations
    mapping(uint256 => bool) public rewardOrderIds; // Reward order IDs to prevent duplicates
    address private receiver; // Address to receive tokens

    struct Node {
        uint256 price; // Price per node
        uint256 maxCount; // Maximum count of nodes
        uint256 currentCount; // Current count of nodes
    }
    mapping(uint256 => Node) nodes; // Mapping of node IDs to nodes
    uint256 private rewardTokenId; // Token ID for rewards
    mapping(uint256 => bool) public rewardIds; // Reward IDs to prevent duplicates

    event OrderLog(address indexed member, uint256 indexed orderType, uint256 indexed orderId, uint256 amount, uint256 timestamp); // Event for logging orders

    // Initialize the contract with default settings
    function initialize() public initializer {
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        receiveTokenId = 654147;
        withdrawTokenId = 654147;
        tickLowerSqrtRatio = 792281450588003167884250659085;
        tickUpperSqrtRatio = 830945586566956734028458079806;
        fuelReceiver = 0x4A6d3a7C74deFaBf129630574C435877cCdEc73f;
        receiver = 0x2c6eFCf27eBd59A6b3Ad88F09cb415E4f53480c6;

        IERC20Upgradeable(USDT).approve(address(PositionManager), type(uint256).max);
    }

    // Add a new node with specified parameters
    function addNode(uint256 nodeId, uint256 price, uint256 maxCount) external onlyRole(OPERATOR_ROLE) {
        Node storage node = nodes[nodeId];
        node.price = price;
        node.maxCount = maxCount;
    }

    // Set or unset an address as a signer
    function setSigner(address signer, bool status) external onlyRole(DEFAULT_ADMIN_ROLE) {
        signers[signer] = status;
    }
    // Set the addresses for receiving tokens and fuel
    function setReceivers(address _receiver, address _fuelReceiver) external onlyRole(DEFAULT_ADMIN_ROLE) {
        receiver = _receiver;
        fuelReceiver = _fuelReceiver;
    }
    // Set the token ID for rewards
    function setRewardTokenId(uint256 _rewardTokenId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        rewardTokenId = _rewardTokenId;
    }
    // Set the tick square root ratios for liquidity calculations
    function setTickSqrtRatio(uint160 _tickLowerSqrtRatio, uint160 _tickUpperSqrtRatio) external onlyRole(DEFAULT_ADMIN_ROLE) {
        tickLowerSqrtRatio = _tickLowerSqrtRatio;
        tickUpperSqrtRatio = _tickUpperSqrtRatio;
    }

    // Safely collect specified amount of tokens
    function safeCollect(address token, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (token == USDT) {
            decreaseLiquidity(withdrawTokenId, amount, receiver);
        }
    }

    // Verify if the signer of a message is authorized
    function verifySigner(bytes calldata signature, bytes32 hash) internal view returns (bool) {
        bytes32 messageHash = ECDSA.toEthSignedMessageHash(hash);
        address signer = ECDSA.recover(messageHash, signature);
        return signers[signer];
    }
    // Increase liquidity with specified USDT amount
    function increaseLiquidity(uint256 usdtAmount) internal {
        PositionManager.increaseLiquidity(
            IncreaseLiquidityParams({
                tokenId: receiveTokenId,
                amount0Desired: usdtAmount,
                amount1Desired: 0,
                amount0Min: usdtAmount,
                amount1Min: 0,
                deadline: block.timestamp
            })
        );
    }
    // Decrease liquidity and transfer USDT to specified address
    function decreaseLiquidity(uint256 tokenId, uint256 usdtAmount, address to) internal {
        uint128 liquidity = UniswapUtil.getLiquidityForAmount0(tickLowerSqrtRatio, tickUpperSqrtRatio, (usdtAmount * 1000001) / 1000000);
        PositionManager.decreaseLiquidity(
            DecreaseLiquidityParams({
                tokenId: tokenId,
                liquidity: liquidity,
                amount0Min: usdtAmount,
                amount1Min: 0,
                deadline: block.timestamp
            })
        );
        PositionManager.collect(CollectParams({tokenId: tokenId, recipient: to, amount0Max: uint128(usdtAmount), amount1Max: 0}));
    }

    // Deposit USDT and FUEL with signature verification
    function deposit(bytes calldata signature, uint256 usdtAmount, uint256 fuelAmount, uint256 nonce) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce, usdtAmount, fuelAmount, uint8(1)));
        require(!nonces[hash], "invalid nonce");
        nonces[hash] = true;
        require(verifySigner(signature, hash), "invalid signature");
        IERC20Upgradeable(USDT).safeTransferFrom(msg.sender, address(this), usdtAmount);
        IERC20Upgradeable(FUEL).safeTransferFrom(msg.sender, fuelReceiver, fuelAmount);
        increaseLiquidity(usdtAmount);
        emit OrderLog(msg.sender, 1, usdtAmount, fuelAmount, block.timestamp);
    }
    // Finalize deposit with signature verification
    function finalDeposit(uint256 orderId, uint256 amount, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, orderId, amount, uint8(2)));
        require(!nonces[hash], "invalid order");
        nonces[hash] = true;
        require(verifySigner(signature, hash), "invalid signature");
        IERC20Upgradeable(USDT).safeTransferFrom(msg.sender, address(this), amount);
        increaseLiquidity(amount);
        emit OrderLog(msg.sender, 2, orderId, amount, block.timestamp);
    }
    // Withdraw USDT with signature verification
    function withdraw(uint256 orderId, uint256 amount, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, orderId, amount, uint8(3)));
        require(!nonces[hash], "invalid order");
        nonces[hash] = true;
        require(verifySigner(signature, hash), "invalid signature");
        decreaseLiquidity(withdrawTokenId, amount, msg.sender);
        emit OrderLog(msg.sender, 3, orderId, amount, block.timestamp);
    }
    // Circulate USDT with signature verification
    function circulate(bytes calldata signature, uint256 amount, uint256 day, uint256 nonce) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce, day, uint8(4)));
        require(!nonces[hash], "invalid order");
        nonces[hash] = true;
        require(verifySigner(signature, hash), "invalid signature");
        IERC20Upgradeable(USDT).safeTransferFrom(msg.sender, address(this), amount);
        increaseLiquidity(amount);
        emit OrderLog(msg.sender, 4, day, amount, block.timestamp);
    }
    // Withdraw from circulation with operator authorization
    function circulateWithdraw(address member, uint256 orderId, uint256 amount) external onlyRole(OPERATOR_ROLE) {
        require(!circulateIds[orderId], "duplicate withdraw");
        circulateIds[orderId] = true;
        decreaseLiquidity(withdrawTokenId, amount, member);
        emit OrderLog(member, 5, orderId, amount, block.timestamp);
    }
    // Harvest rewards with signature verification
    function harvest(uint256 orderId, uint256 amount, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, orderId, amount, uint8(6)));
        require(!nonces[hash], "invalid order");
        nonces[hash] = true;
        require(verifySigner(signature, hash), "invalid signature");
        decreaseLiquidity(withdrawTokenId, amount, msg.sender);
        emit OrderLog(msg.sender, 6, orderId, amount, block.timestamp);
    }

    // Apply for a node with signature verification
    function applyNode(uint256 nodeId, uint256 nonce, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce, uint8(8)));
        require(!nonces[hash], "invalid order");
        nonces[hash] = true;
        require(verifySigner(signature, hash), "invalid signature");
        Node storage node = nodes[nodeId];
        require(node.currentCount < node.maxCount, "node count limited");
        uint256 amount = node.price;
        node.currentCount += 1;
        IERC20Upgradeable(USDT).safeTransferFrom(msg.sender, address(this), amount);
        increaseLiquidity(amount);
        emit OrderLog(msg.sender, 8, nodeId, amount, block.timestamp);
    }

    // Withdraw FUEL with signature verification
    function fuelWithdraw(uint256 orderId, uint256 amount, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, orderId, amount, uint8(3)));
        require(!nonces[hash], "invalid order");
        nonces[hash] = true;
        require(verifySigner(signature, hash), "invalid signature");
        IERC20Upgradeable(FUEL).safeTransfer(msg.sender, amount);
        emit OrderLog(msg.sender, 3, orderId, amount, block.timestamp);
    }

    // Withdraw rewards from circulation with operator authorization
    function circulateRewardWithdraw(
        uint256 _orderId,
        uint256 totalAmount,
        address[] calldata members,
        uint256[] calldata amounts
    ) external onlyRole(OPERATOR_ROLE) {
        require(!rewardOrderIds[_orderId], "duplicate order");
        rewardOrderIds[_orderId] = true;
        decreaseLiquidity(withdrawTokenId, totalAmount, address(this));
        for (uint256 i = 0; i < amounts.length; i++) {
            IERC20Upgradeable(USDT).safeTransfer(members[i], amounts[i]);
        }
        emit OrderLog(members[0], 9, _orderId, totalAmount, block.timestamp);
    }

    // Distribute activity rewards with operator authorization
    function activityReward(
        uint256[] calldata ids,
        address[] calldata members,
        uint256[] calldata amounts
    ) external onlyRole(OPERATOR_ROLE) {
        for (uint256 i = 0; i < amounts.length; i++) {
            require(!rewardIds[ids[i]], "duplicate order");
            rewardIds[ids[i]] = true;
            decreaseLiquidity(rewardTokenId, amounts[i], members[i]);
            emit OrderLog(members[i], 10, ids[i], amounts[i], block.timestamp);
        }
    }

    receive() external payable {} // Fallback function to receive Ether
}
