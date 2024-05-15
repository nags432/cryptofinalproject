async function main() {
    const [deployer] = await ethers.getSigners();

    console.log("Deploying contracts with the account:", deployer.address);

    const AttestorRegistry = await ethers.getContractFactory("AttestorRegistry");
    const attestorRegistry = await AttestorRegistry.deploy();

    console.log("AttestorRegistry deployed to:", attestorRegistry.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
      console.error(error);
      process.exit(1);
  });
