import express, { Router } from "express";
import { setCustomClaims, getUserDetails } from "../controllers/adminController";
import { authenticate } from "../middleware/authenticate";
import { authorize } from "../middleware/authorize";
 
const router: Router = express.Router();
 
// Only authenticated admins can set claims
router.post(
  "/setCustomClaims",
  authenticate,
  authorize({ roles: ["admin"] }),
  setCustomClaims
);
 
// Only admins can view user details
router.get(
  "/:uid",
  authenticate,
  authorize({ roles: ["admin"] }),
  getUserDetails
);
 
export default router;