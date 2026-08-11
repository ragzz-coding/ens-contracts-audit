// SPDX-License-Identifier: MIT
pragma solidity ~0.8.17;

import {IPriceOracle} from "../ethregistrar/IPriceOracle.sol";

/// @notice Fixed-price oracle for H2 harness (not production StablePriceOracle).
contract MockPriceOracle is IPriceOracle {
    uint256 public immutable basePrice;

    constructor(uint256 _basePrice) {
        basePrice = _basePrice;
    }

    function price(
        string calldata /* name */,
        uint256 /* expires */,
        uint256 /* duration */
    ) external view override returns (Price memory) {
        return Price({base: basePrice, premium: 0});
    }
}
