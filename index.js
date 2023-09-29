const cluster = require('cluster');
const os = require('os');

if (cluster.isMaster) {
  // If it's the master process, fork workers based on the number of CPU cores.
  
  const numCores = os.cpus().length;
  console.log("number of cores "+ os.cpus().length);
  for (let i = 0; i < numCores; i++) {
    cluster.fork();
  }

  // Listen for worker exit events and fork a new worker if one exits.
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    cluster.fork();
  });
} else {
  // If it's a worker process, create an Express app and set up routes.
  const express = require('express');
  const routes = require('./routes/routes');
  const app = express();
 
  const PORT = process.env.PORT || 3030;

  app.enable('trust proxy');
  app.use(express.json());
  app.use('/api', routes);

  app.listen(PORT, () => {
    console.log(`Worker ${process.pid} is running on port ${PORT}`);
  });
}