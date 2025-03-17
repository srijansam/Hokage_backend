# Hokage Anime Backend

This is the backend server for the Hokage Anime application.

## Setup Instructions

1. Install dependencies:
   ```
   npm install
   ```

2. Create a `.env` file in the root directory with the following variables:
   ```
   MONGO_URI=your_mongodb_connection_string
   YOUTUBE_API_KEY=your_youtube_api_key
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   CALLBACK_URL=http://localhost:5001/auth/google/callback
   JWT_SECRET=your_jwt_secret
   
   # Email Configuration
   EMAIL_USER=your.email@gmail.com
   EMAIL_PASSWORD=your_app_password
   ```

3. Start the server:
   ```
   npm start
   ```

## Email Configuration for Password Reset

The password reset functionality requires email sending capabilities. Follow these steps to set up email with Gmail:

### Setting up Gmail for sending emails:

1. **Create or use an existing Gmail account** that you want to use for sending password reset emails.

2. **Enable 2-Step Verification** for your Google account:
   - Go to your Google Account settings: https://myaccount.google.com/
   - Select "Security" from the left menu
   - Under "Signing in to Google," select "2-Step Verification" and follow the steps to turn it on

3. **Generate an App Password**:
   - After enabling 2-Step Verification, go back to the Security page
   - Under "Signing in to Google," select "App passwords"
   - Select "Mail" as the app and "Other" as the device (name it "Hokage Anime")
   - Click "Generate"
   - Google will display a 16-character app password. **Copy this password**

4. **Update your .env file**:
   ```
   EMAIL_USER=your.gmail.account@gmail.com
   EMAIL_PASSWORD=your_16_character_app_password
   ```

5. **Restart your server** after making these changes.

### Troubleshooting Email Issues:

- If you see "Email configuration error" in the console, check that your app password is correct
- Make sure 2-Step Verification is enabled for your Google account
- If using a Google Workspace account, ensure API access is enabled
- For security reasons, Google may block sign-in attempts. Check your email for any security alerts

### Testing the Email Service:

When a user requests a password reset, the verification code will be:
1. Sent to their email (if email is configured correctly)
2. Logged to the console (as a fallback)

For development purposes, you can use the console logs to get the verification code if email sending fails. 