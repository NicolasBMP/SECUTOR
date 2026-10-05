import { Injectable } from "@nestjs/common";
import { HttpAdapter } from "../interfaces/http-adaper.interface";
import axios, { AxiosInstance } from "axios";

@Injectable()
export class AxiosAdapter implements HttpAdapter {
    private readonly axios: AxiosInstance = axios;

    async get<T>(url: string, header: any, data: any): Promise<T> {
        try {
            const resp = await this.axios.get<T>(url, {
                headers: header,
                data: data
            });
            return resp.data;
        }
        catch (error) {
            throw new Error(`ERROR EN PETICIÓN GET: ${error}`);
        }
    }

    async post<T>(url: string, header: any, data: any): Promise<T> {
        try {
            const resp = await this.axios.post<T>(url, {
                headers: header,
                data: data
            });
            return resp.data;
        }
        catch (error) {
            throw new Error(`ERROR EN PETICIÓN POST: ${error}`);
        }
    }
}
