import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import express from 'express';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand, DeleteCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { CognitoIdentityProviderClient, SignUpCommand, ConfirmSignUpCommand, InitiateAuthCommand, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = 3000;

// Environment variable checks
const AWS_REGION = process.env.AWS_REGION;
const TABLE_NAME = process.env.TABLE_NAME;
const BUCKET_NAME = process.env.BUCKET_NAME;
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID;

if (!AWS_REGION) {
  console.error('Error: AWS_REGION environment variable is not set.');
  process.exit(1);
}
if (!TABLE_NAME) {
  console.error('Error: TABLE_NAME environment variable is not set.');
  process.exit(1);
}
if (!BUCKET_NAME) {
  console.error('Error: BUCKET_NAME environment variable is not set.');
  process.exit(1);
}
if (!COGNITO_CLIENT_ID) {
  console.error('Error: COGNITO_CLIENT_ID environment variable is not set.');
  process.exit(1);
}

// AWS Clients
const dbClient = new DynamoDBClient({ region: AWS_REGION });
const db = DynamoDBDocumentClient.from(dbClient);
const s3 = new S3Client({ region: AWS_REGION });
const idp = new CognitoIdentityProviderClient({ region: AWS_REGION });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper to parse cookies
function parseCookie(cookieHeader) {
  const list = {};
  String(cookieHeader || '').split(';').forEach(function(cookie) {
    const parts = cookie.split('=');
    if (parts.length > 1) {
      list[parts[0].trim()] = parts.slice(1).join('=').trim();
    }
  });
  return list;
}

// Middleware to require user authentication
async function requireUser(req, res, next) {
  try {
    const cookies = parseCookie(req.headers.cookie);
    const accessToken = cookies.at;

    if (!accessToken) {
      return res.status(401).json({ message: 'Authentication required.' });
    }

    const command = new GetUserCommand({ AccessToken: accessToken });
    const response = await idp.send(command);

    const userAttributes = response.UserAttributes.reduce((acc, attr) => {
      acc[attr.Name] = attr.Value;
      return acc;
    }, {});

    req.user = {
      sub: userAttributes.sub,
      email: userAttributes.email
    };
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send('ok');
});

// --- Cognito Authentication Routes ---

app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const command = new SignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      Username: email,
      Password: password,
      UserAttributes: [{ Name: 'email', Value: email }]
    });
    await idp.send(command);
    res.status(200).json({ message: 'User signed up successfully. Please confirm your email.' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(400).json({ message: err.message });
  }
});

app.post('/auth/confirm', async (req, res) => {
  try {
    const { email, code } = req.body;
    const command = new ConfirmSignUpCommand({
      ClientId: COGNITO_CLIENT_ID,
      Username: email,
      ConfirmationCode: code
    });
    await idp.send(command);
    res.status(200).json({ message: 'Email confirmed successfully. You can now log in.' });
  } catch (err) {
    console.error('Confirm signup error:', err);
    res.status(400).json({ message: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const command = new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: COGNITO_CLIENT_ID,
      AuthParameters: { USERNAME: email, PASSWORD: password }
    });
    const result = await idp.send(command);

    if (!result.AuthenticationResult) {
      return res.status(400).json({ message: 'Authentication failed.' });
    }

    res.setHeader('Set-Cookie', 'at=' + result.AuthenticationResult.AccessToken + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=3300');
    res.status(200).json({ message: 'Logged in successfully.' });
  } catch (err) {
    console.error('Login error:', err);
    if (err.name === 'UserNotConfirmedException') {
      return res.status(403).json({ code: 'NOT_CONFIRMED', message: 'User not confirmed. Please confirm your email.' });
    }
    res.status(400).json({ message: err.message });
  }
});

app.post('/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'at=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.status(200).json({ message: 'Logged out successfully.' });
});

app.get('/auth/me', requireUser, (req, res) => {
  res.status(200).json({ email: req.user.email });
});

// --- S3 and DynamoDB Photo Management Routes ---

// Upload file to S3
app.post('/upload', requireUser, express.raw({ type: function () { return true; }, limit: '10mb' }), async (req, res) => {
  try {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ message: 'Request body must be a non-empty buffer.' });
    }

    const safeName = String(req.query.name || 'file').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 100);
    const s3Key = 'uploads/' + req.user.sub + '/' + randomUUID() + '-' + safeName;
    const contentType = req.headers['content-type'] || 'application/octet-stream';

    const command = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key,
      Body: req.body,
      ContentType: contentType
    });
    await s3.send(command);

    res.status(200).json({
      s3Key: s3Key,
      name: safeName,
      size: req.body.length,
      contentType: contentType,
      createdAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('S3 upload error:', err);
    res.status(500).json({ message: 'Failed to upload file.' });
  }
});

// Add photo metadata to DynamoDB
app.post('/photos', requireUser, async (req, res) => {
  try {
    const { s3Key, name, size, contentType, createdAt, title, description } = req.body;

    // Validate s3Key belongs to the user
    const userPrefix = 'uploads/' + req.user.sub + '/';
    if (!s3Key || !s3Key.startsWith(userPrefix) || !s3Key.match(/^uploads[/][A-Za-z0-9-]+[/][A-Za-z0-9._-]+$/)) {
      return res.status(400).json({ message: 'Invalid S3 key or key does not belong to user.' });
    }

    const photoId = randomUUID();
    const item = {
      pk: 'USER#' + req.user.sub,
      sk: 'PHOTO#' + photoId,
      photoId: photoId,
      s3Key: s3Key,
      name: name,
      size: size,
      contentType: contentType,
      createdAt: createdAt,
      title: title || '',
      description: description || ''
    };

    const command = new PutCommand({
      TableName: TABLE_NAME,
      Item: item
    });
    await db.send(command);

    res.status(201).json(item);
  } catch (err) {
    console.error('DynamoDB add photo error:', err);
    res.status(500).json({ message: 'Failed to save photo metadata.' });
  }
});

// List photos for the logged-in user
app.get('/photos', requireUser, async (req, res) => {
  try {
    const command = new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: {
        ':pk': 'USER#' + req.user.sub
      },
      FilterExpression: 'begins_with(sk, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': 'USER#' + req.user.sub,
        ':skPrefix': 'PHOTO#'
      }
    });
    const result = await db.send(command);
    res.status(200).json(result.Items || []);
  } catch (err) {
    console.error('DynamoDB list photos error:', err);
    res.status(500).json({ message: 'Failed to retrieve photos.' });
  }
});

// Download file from S3
app.get('/download', requireUser, async (req, res) => {
  try {
    const s3Key = req.query.key;

    // Validate s3Key belongs to the user
    const userPrefix = 'uploads/' + req.user.sub + '/';
    if (!s3Key || !s3Key.startsWith(userPrefix) || !s3Key.match(/^uploads[/][A-Za-z0-9-]+[/][A-Za-z0-9._-]+$/)) {
      return res.status(400).json({ message: 'Invalid S3 key or key does not belong to user.' });
    }

    const command = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key
    });
    const result = await s3.send(command);

    if (!result.Body) {
      return res.status(404).json({ message: 'File not found.' });
    }

    const contentType = result.ContentType || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const inlineTypes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
    if (inlineTypes.includes(contentType)) {
      res.setHeader('Content-Disposition', 'inline');
    } else {
      res.setHeader('Content-Disposition', 'attachment');
    }

    result.Body.pipe(res);
  } catch (err) {
    console.error('S3 download error:', err);
    if (err.name === 'NoSuchKey') {
      return res.status(404).json({ message: 'File not found.' });
    }
    res.status(500).json({ message: 'Failed to download file.' });
  }
});

// Delete photo metadata from DynamoDB and object from S3
app.delete('/photos/:id', requireUser, async (req, res) => {
  try {
    const photoId = req.params.id;
    const pk = 'USER#' + req.user.sub;
    const sk = 'PHOTO#' + photoId;

    // Get item to retrieve s3Key
    const getCommand = new GetCommand({
      TableName: TABLE_NAME,
      Key: { pk: pk, sk: sk }
    });
    const { Item } = await db.send(getCommand);

    if (!Item) {
      return res.status(404).json({ message: 'Photo not found.' });
    }

    const s3Key = Item.s3Key;

    // Validate s3Key belongs to the user before deleting from S3
    const userPrefix = 'uploads/' + req.user.sub + '/';
    if (!s3Key || !s3Key.startsWith(userPrefix) || !s3Key.match(/^uploads[/][A-Za-z0-9-]+[/][A-Za-z0-9._-]+$/)) {
      // This should ideally not happen if the item was retrieved correctly, but as a safeguard
      console.warn('Attempted to delete S3 key not matching user prefix:', s3Key, 'for user:', req.user.sub);
      return res.status(400).json({ message: 'Invalid S3 key associated with photo or key does not belong to user.' });
    }

    // Delete from S3
    const deleteS3Command = new DeleteObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key
    });
    await s3.send(deleteS3Command);

    // Delete from DynamoDB
    const deleteDbCommand = new DeleteCommand({
      TableName: TABLE_NAME,
      Key: { pk: pk, sk: sk }
    });
    await db.send(deleteDbCommand);

    res.status(200).json({ message: 'Photo deleted successfully.' });
  } catch (err) {
    console.error('Delete photo error:', err);
    res.status(500).json({ message: 'Failed to delete photo.' });
  }
});

// Update photo metadata in DynamoDB
app.put('/photos/:id', requireUser, async (req, res) => {
  try {
    const photoId = req.params.id;
    const { title, description } = req.body;
    const pk = 'USER#' + req.user.sub;
    const sk = 'PHOTO#' + photoId;

    const command = new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { pk: pk, sk: sk },
      UpdateExpression: 'SET title = :title, description = :description',
      ExpressionAttributeValues: {
        ':title': title || '',
        ':description': description || ''
      },
      ReturnValues: 'ALL_NEW'
    });
    const result = await db.send(command);

    if (!result.Attributes) {
      return res.status(404).json({ message: 'Photo not found.' });
    }

    res.status(200).json(result.Attributes);
  } catch (err) {
    console.error('Update photo error:', err);
    res.status(500).json({ message: 'Failed to update photo metadata.' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('Server running on http://0.0.0.0:' + PORT);
});
