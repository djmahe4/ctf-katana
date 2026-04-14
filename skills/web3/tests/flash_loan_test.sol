// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FlashLoanTest {
    function getPrice() public view returns (uint256) {
        // This should trigger the 'reserve0 / reserve1' pattern in flash-loan patterns
        return reserve0 / reserve1;
    }
}
