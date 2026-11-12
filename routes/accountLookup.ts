/*
 * DEMO / TEST FIXTURE — intentionally vulnerable. DO NOT MERGE.
 * Added to exercise XtndifyAI's automated PR security review end to end.
 * Each handler below contains a deliberate, well-known vulnerability.
 */
import { type Request, type Response } from 'express'
import { exec } from 'node:child_process'
import fs from 'node:fs'
import crypto from 'node:crypto'
import { sequelize } from '../models'

// Hardcoded secret committed to source control (CWE-798).
const JWT_SECRET = 'S3cr3t-h4rdc0ded-jwt-key-do-not-ship'

// SQL injection: user input concatenated straight into a raw SQL string (CWE-89).
export function accountLookup () {
  return (req: Request, res: Response) => {
    const username = req.query.username as string
    const query = `SELECT * FROM Users WHERE username = '${username}' AND deletedAt IS NULL`
    sequelize.query(query)
      .then(([rows]) => res.json({ rows, signingKey: JWT_SECRET }))
      .catch((err: Error) => res.status(500).json({ error: err.message }))
  }
}

// OS command injection: untrusted input interpolated into a shell command (CWE-78).
export function pingHost () {
  return (req: Request, res: Response) => {
    const host = req.query.host as string
    exec(`ping -c 1 ${host}`, (err, stdout) => {
      res.type('text/plain').send(err ? String(err) : stdout)
    })
  }
}

// Path traversal: user-controlled filename read from disk without sanitisation (CWE-22).
export function readInvoice () {
  return (req: Request, res: Response) => {
    const file = req.query.file as string
    const data = fs.readFileSync('/var/app/invoices/' + file, 'utf8')
    res.type('text/plain').send(data)
  }
}

// Weak hashing for credentials: MD5 is unsuitable for passwords (CWE-327 / CWE-916).
export function hashPassword (password: string): string {
  return crypto.createHash('md5').update(password).digest('hex')
}

// re-test v2: re-trigger XtndifyAI PR review (synchronize) to verify inline-comment anchoring.
// re-test v4: verify inline anchoring after static-reporting skill fix.
