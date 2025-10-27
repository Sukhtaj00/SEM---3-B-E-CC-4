import { Request, Response, NextFunction } from "express";
import { UserRecord } from "firebase-admin/auth";
import { auth } from "src/config/firebaseConfig";
import { HTTP_STATUS } from "../../../constants/httpConstants";
 
/**
* POST /api/v1/admin/setCustomClaims
* Body: { "uid": "user-id", "claims": { "role": "admin" } }
*/
export const setCustomClaims = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const { uid, claims } = req.body;
 
  if (!uid || !claims) {
    res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      message: "Missing uid or claims in request body",
    });
    return;
  }
 
  try {
    await auth.setCustomUserClaims(uid, claims);
    res.status(HTTP_STATUS.OK).json({
      success: true,
      message: `Custom claims set for user: ${uid}`,
    });
  } catch (error) {
    next(error);
  }
};
 
/**
* GET /api/v1/admin/:uid
* Returns Firebase Auth user details
*/
export const getUserDetails = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const { uid } = req.params;
 
  try {
    const user: UserRecord = await auth.getUser(uid);
    res.status(HTTP_STATUS.OK).json({
      success: true,
      data: user,
    });
  } catch (error) {
    next(error);
  }
};