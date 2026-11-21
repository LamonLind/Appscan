# Appscan

Native Android app that scans an IPv4 CIDR or a text host-file with HEAD requests.

## Upload to GitHub

1. Create a new GitHub repository.
2. From this project directory, run:
   ```sh
   git init
   git add .
   git commit -m "Add Appscan Android app"
   git branch -M main
   git remote add origin https://github.com/<owner>/<repo>.git
   git push -u origin main
   ```
3. Open the repository's **Actions** tab and open the latest **Android release** run.
4. Download **app-release** from the run’s Artifacts section. The APK is rejected by the workflow if it exceeds 3 MB (3,145,728 bytes).