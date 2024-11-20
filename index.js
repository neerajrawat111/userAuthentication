const express = require('express');
const dotenv = require('dotenv'); 
const authRoutes = require('./routes/authRoutes');

dotenv.config(); 

const app = express();


app.use(express.json()); 


app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;  
app.listen(PORT, () => {
  console.log(`Backend server is running at http://localhost:${PORT}`);
});

app.get('/', (req, res) => {
  console.log("working");
  res.send("Server is working");  
});

module.exports=  app;