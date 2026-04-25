import NextAuth from "next-auth";
import GitHub from "next-auth/providers/github";
import Google from "next-auth/providers/google";
import Credentials from "next-auth/providers/credentials";
import { DrizzleAdapter } from "@auth/drizzle-adapter";
import { eq } from "drizzle-orm";
import bcrypt from "bcryptjs";
import { db } from "./db";
import { users, accounts } from "./schema";

export const { handlers, auth, signIn, signOut } = NextAuth({
  adapter: DrizzleAdapter(db, {
    usersTable: users,
    accountsTable: accounts,
  }),
  session: { strategy: "jwt" },
  providers: [
    Credentials({
      credentials: {
        email:    { label: "Email",    type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (typeof credentials.email !== "string" || typeof credentials.password !== "string") return null;

        const [user] = await db
          .select()
          .from(users)
          .where(eq(users.email, credentials.email))
          .limit(1);

        if (!user?.passwordHash) return null;
        const valid = await bcrypt.compare(credentials.password, user.passwordHash);
        if (!valid) return null;

        return { id: user.id, email: user.email, name: user.name ?? null, image: user.image ?? null };
      },
    }),
    ...(process.env["AUTH_GITHUB_ID"] && process.env["AUTH_GITHUB_SECRET"]
      ? [GitHub({ clientId: process.env["AUTH_GITHUB_ID"], clientSecret: process.env["AUTH_GITHUB_SECRET"] })]
      : []),
    ...(process.env["AUTH_GOOGLE_ID"] && process.env["AUTH_GOOGLE_SECRET"]
      ? [Google({ clientId: process.env["AUTH_GOOGLE_ID"], clientSecret: process.env["AUTH_GOOGLE_SECRET"] })]
      : []),
  ],
  pages: {
    signIn:  "/login",
    signOut: "/logout",
    error:   "/login",
  },
  callbacks: {
    jwt({ token, user }) {
      if (user?.id) token.id = user.id;
      return token;
    },
    session({ session, token }) {
      if (session.user && token.id) session.user.id = token.id as string;
      return session;
    },
  },
});
