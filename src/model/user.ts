import {z} from "zod";

export const UserSchema =  z.object({
    email: z.string().email(),
    secret: z.string(),
    name: z.string(),
    salt: z.string(),
});

export type User = z.infer<typeof UserSchema>;