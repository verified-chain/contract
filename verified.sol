// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

abstract contract ERC677Receiver {
    /**
     * @dev Method invoked when tokens transferred via transferAndCall method
     * @param sender Original token sender
     * @param value Tokens amount
     * @param data Additional data passed to contract
     */
    function onTokenTransfer(
        address sender,
        uint256 value,
        bytes calldata data
    ) external virtual;
}

contract Verified is VRFConsumerBaseV2, ChainlinkClient, ERC677Receiver {
    address linkTokenContract = 0x84b9B910527Ad5C03A9Ca831909E21e236EA7b06;
    uint256 constant NULL = 0;

    // VRF
    VRFCoordinatorV2Interface COORDINATOR;
    LinkTokenInterface LINKTOKEN;
    uint64 public s_subscriptionId;
    address vrfCoordinator = 0x6A2AAd07396B36Fe02a22b33cf443582f682c82f;
    bytes32 keyHash = 0xd4bb89654db74673a187bd804519e65e3f71a52bc55f11da7601a13dcf505314;
    uint32 callbackGasLimit = 200000;
    uint16 requestConfirmations = 3;
    uint256 fee = 0.1 * 10 ** 18;

    // ORACLE
    address private oracle = 0xc897AB197611d16e4ABD18878aba8c85c8f370a9;
    bytes32 private jobId = "fb4b27d00d704c3da5e16282e705f190";
    uint256 oracle_fee = 0.1 * 10 ** 18;

    // VERIFIED SPECIFIC
    struct Request
    {
        string URL;
        string selector;
        uint256 challenge;
        uint256 balance;
    }

    struct Verification
    {
        string timestamp;
        string URL;
        string selector;
    }

    mapping (address => Request) requests;
    mapping (address => Verification[]) allVerifications;
    mapping (uint256 => address) VRFRequestIds;
    mapping (bytes32 => address) oracleRequestIds;

    // EVENTS
    event ValidationUpdate(address requester, uint256 challenge);
    event VerificationResult(address requester, bool verified, string URL, string selector);
    event VerificationForAddress(address requester, string verificationTimestamp, string URL, string selector);
    event PaymentSet(address requester, uint256 balance);

    using Chainlink for Chainlink.Request;
    constructor() VRFConsumerBaseV2(vrfCoordinator) {
        COORDINATOR = VRFCoordinatorV2Interface(vrfCoordinator);
        LINKTOKEN = LinkTokenInterface(linkTokenContract);
        setChainlinkToken(linkTokenContract);
        createNewSubscription();
    }

    function getVerificationsForAddress(address addr) public {
        Verification[] memory verificationsForAddr = allVerifications[addr];
        uint arrayLength = verificationsForAddr.length;
        for (uint i=0; i<arrayLength; i++) {
            emit VerificationForAddress(addr, verificationsForAddr[i].timestamp,
                verificationsForAddr[i].URL,
                verificationsForAddr[i].selector);
        }
    }

    function requestVerification(string calldata URL, string calldata selector) public {
        Request storage rq = requests[msg.sender];
        if (rq.balance < fee)
            revert("Please send 0.1 LINK (request) and 0.1 LINK (per 'verify' call) to this contract address");
        rq.balance -= fee;
        rq.URL = URL;
        rq.selector = selector;
        rq.challenge = NULL;
        emit ValidationUpdate(msg.sender, rq.challenge);
        LINKTOKEN.transferAndCall(address(COORDINATOR), fee, abi.encode(s_subscriptionId));
        uint256 requestId = COORDINATOR.requestRandomWords(
            keyHash,
            s_subscriptionId,
            requestConfirmations,
            callbackGasLimit,
            1
        );
        VRFRequestIds[requestId] = msg.sender;
    }

    function onTokenTransfer(
        address sender,
        uint256 value,
        bytes calldata data
    ) external override linkTokenOnly {
        Request storage rq = requests[sender];
        rq.balance += value;
        emit PaymentSet(sender, rq.balance);
    }

    modifier linkTokenOnly() {
        require(msg.sender == address(LINKTOKEN), "Tokens can only be sent via LINK");
        _;
    }

    function fulfillRandomWords(
        uint256 requestId,
        uint256[] memory randomWords
    ) internal override {
        address initiator = VRFRequestIds[requestId];
        requests[initiator].challenge = randomWords[0];
        emit ValidationUpdate(initiator, requests[initiator].challenge);
    }

    function createNewSubscription() private {
        address[] memory consumers = new address[](1);
        consumers[0] = address(this);
        s_subscriptionId = COORDINATOR.createSubscription();
        COORDINATOR.addConsumer(s_subscriptionId, consumers[0]);
    }

    function verify() public
    {
        Request storage rq = requests[msg.sender];

        if (rq.balance < fee)
            revert("Please send LINK to this contract address : 0.1 LINK (for the request) and 0.1 LINK (per 'verify' call)");
        rq.balance -= fee;
        if (rq.challenge == NULL)
            revert("Please wait for the challenge to be generated");
        if (bytes(rq.URL).length == NULL)
            revert("Missing required parameters for verification : URL)");
        if (bytes(rq.selector).length == NULL)
            revert("Missing required parameters for verification : selector)");

        Chainlink.Request memory oracle_request = buildChainlinkRequest(jobId, address(this), this.fulfill.selector);
        oracle_request.add("url", rq.URL);
        oracle_request.add("selector", rq.selector);
        oracle_request.add("challenge", Strings.toString(rq.challenge));
        bytes32 oracleRequestId = sendChainlinkRequestTo(oracle, oracle_request, oracle_fee);
        oracleRequestIds[oracleRequestId] = msg.sender;
    }

    function fulfill(bytes32 _requestId, bool _value) public recordChainlinkFulfillment(_requestId)
    {
        address initiator = oracleRequestIds[_requestId];
        if (_value == true) {
            Verification memory vr = Verification({URL: requests[initiator].URL, selector: requests[initiator].selector, timestamp: Strings.toString(block.timestamp) });
            Verification[] storage verifications = allVerifications[initiator];
            verifications.push(vr);
        }
        emit VerificationResult(initiator, _value, requests[initiator].URL, requests[initiator].selector);
        requests[initiator].URL = "";
        requests[initiator].selector = "";
        requests[initiator].challenge = NULL;
    }
}
