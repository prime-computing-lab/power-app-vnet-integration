https://github.com/microsoft/PowerApps-Samples.git

# 1. Create and enter a new folder for your sparse repo
mkdir PowerApps-Samples-Sparse
cd PowerApps-Samples-Sparse

# 2. Initialize a new git repo
git init

# 3. Add the remote origin
git remote add origin https://github.com/microsoft/PowerApps-Samples.git

# 4. Enable sparse checkout
git config core.sparseCheckout true

# 5. Define the subdirectory you want (e.g., powershell/enterprisePolicies)
echo "powershell/enterprisePolicies/" >> .git/info/sparse-checkout

# 6. Pull the latest content from the remote
git pull origin master
