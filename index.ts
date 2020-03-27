'use strict';
import express from 'express';
import bodyParser from 'body-parser';
import router from './routes/index';
import cors from 'cors';

const port: number = 3000;
const app: express.Application = express();

app.use(cors({origin:'http://localhost:4200'}));
app.use( express.json() );
app.use( '', router );
app.use( bodyParser.json() );

app.listen(port, function () {
    console.log('Listening on http://localhost:' + port);
});
