const hre = require("hardhat");

async function main() {
  const TrustChain = await hre.ethers.getContractFactory("TrustChain");
  const trustChain = await TrustChain.deploy();

  // Wait for deployment confirmation
  await trustChain.waitForDeployment();

  console.log("TrustChain deployed to:", trustChain.target);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
