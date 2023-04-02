import { sessionDetails } from "./src/util/session";

declare namespace Express {
    interface Request {
        server?: string
        user?: string,
        headers: { 'session-id': string},
        sessionDetails: sessionDetails,
        query: { name:string, server: string },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        cookies: Record<string, any>,
    }
}