import 'dotenv/config';
import * as joi from 'joi';

interface EnvVarrs {
    PORT: number;
    APP_ENTORNO: string;
    MICROSERVICE_NAME: string;
    CORS: string;
    EMAIL_HOST: string;
    EMAIL_PORT: number;
    EMAIL_USER: string;
    EMAIL_PASS: string;
    EMAIL_TEST: string;
    VERSION: string;
    RATE_LIMIT_TTL: number;
    RATE_LIMIT_LIMIT: number;
    OSV_QUERYBATCH_URL: string;
    OSV_VULN_URL_BASE: string;
}

const envsSchema = joi.object({
    PORT: joi.number().required(),
    APP_ENTORNO: joi.string().required().min(3).default('dev'),
    MICROSERVICE_NAME: joi.string().required(),
    CORS: joi.string().uri().required(),
    EMAIL_HOST: joi.string().required(),
    EMAIL_PORT: joi.number().required(),
    EMAIL_USER: joi.string().email().required(),
    EMAIL_PASS: joi.string().required(),
    EMAIL_TEST: joi.string().email(),
    VERSION: joi.string().required(),
    RATE_LIMIT_TTL: joi.number().default(60000),
    RATE_LIMIT_LIMIT: joi.number().default(30),
    OSV_QUERYBATCH_URL: joi.string().uri().required(),
    OSV_VULN_URL_BASE: joi.string().uri().required()
}).unknown(true);

const { error, value } = envsSchema.validate(process.env);

if (error) {
    throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVarrs = value;

export const envs = {
    port: envVars.PORT,
    app_entorno: envVars.APP_ENTORNO,
    microservice_name: envVars.MICROSERVICE_NAME,
    cors: envVars.CORS,
    email_host: envVars.EMAIL_HOST,
    email_port: envVars.EMAIL_PORT,
    email_user: envVars.EMAIL_USER,
    email_pass: envVars.EMAIL_PASS,
    email_test: envVars.EMAIL_TEST,
    version: envVars.VERSION,
    rate_limit_ttl: envVars.RATE_LIMIT_TTL,
    rate_limit_limit: envVars.RATE_LIMIT_LIMIT,
    osv_querybatch_url: envVars.OSV_QUERYBATCH_URL,
    osv_vuln_url_base: envVars.OSV_VULN_URL_BASE
}
