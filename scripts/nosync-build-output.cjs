const { execFileSync } = require('node:child_process');
if (process.platform === 'darwin' && !process.env.CI) {
  try {
    execFileSync('./scripts/nosync-build-output.sh', { stdio: 'inherit' });
  } catch (err) {
    process.exit(err.status || 1);
  }
}
