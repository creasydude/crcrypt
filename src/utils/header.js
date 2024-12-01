import chalk from "chalk";
import chalkAnimation from "chalk-animation";

const text = `
 _____ _____ _____ _____ __ __ _____ _____ 
|     | __  |     | __  |  |  |  _  |_   _|
|   --|    -|   --|    -|_   _|   __| | |  
|_____|__|__|_____|__|__| |_| |__|    |_|  

By CreasY
`;


export default async function showHeader() {
    process.stdout.write("\x1Bc");
    const animation = chalkAnimation.rainbow(text);
    // Wait for 5 seconds
    await new Promise((resolve) => setTimeout(resolve, 1350));
    animation.stop(); // Stop the animation
    console.log(chalk.green("\nScript is starting...\n"));
    process.stdout.write("\x1Bc");
    console.log(chalk.bgWhite(chalk.black("CRCRYPT Tool for Encrypting and Decrypting Your Data Using the AES Algorithm")));
    console.log("\n");
}
