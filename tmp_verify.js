const { verifyUserData } = require('./backend/services/signingService');
const result = verifyUserData({
  id: 'a3f1fba4-931d-4c5a-80c4-3a60bcc72ab0',
  email: 'mundoalexis1010@gmail.com',
  role: 'authenticated',
  iat: 1776225400,
  exp: 1776229000,
  signature: 'MEUCIQDgWfO2l6rTfmyvk6KjrSUR3RsFSMF5BuWSi4YpKMBzXgIgYOpV+cjlEXFlScKH7dAhmaJwDp6/MvJhIfsFUxgVSxY='
});
console.log(JSON.stringify(result));
