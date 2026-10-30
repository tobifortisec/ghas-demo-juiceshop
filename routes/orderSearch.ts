/*
 * DEMO / TEST FIXTURE — intentionally vulnerable. DO NOT MERGE.
 * Second fixture (fresh endpoints) to verify XtndifyAI inline-comment anchoring on new findings.
 */
import { type Request, type Response } from 'express'
import { exec } from 'node:child_process'
import { sequelize } from '../models'

// SQL injection: order search term concatenated into a raw query (CWE-89).
export function orderSearch () {
  return (req: Request, res: Response) => {
    const q = req.query.q as string
    const sql = "SELECT * FROM Orders WHERE note LIKE '%" + q + "%'"
    sequelize.query(sql).then(([rows]) => res.json(rows))
  }
}

// OS command injection: archive name interpolated into a shell command (CWE-78).
export function exportOrders () {
  return (req: Request, res: Response) => {
    const name = req.query.name as string
    exec('tar czf /tmp/' + name + '.tgz /var/app/orders', (err, stdout) => {
      res.type('text/plain').send(err ? String(err) : stdout)
    })
  }
}
