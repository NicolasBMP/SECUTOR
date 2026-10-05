export interface HttpAdapter {
    get<T>(url: string, header: any, data: any): Promise<T>;
    post<T>(url: string, header: any, data: any): Promise<T>;
}
