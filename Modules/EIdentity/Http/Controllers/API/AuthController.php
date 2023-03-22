<?php


namespace Modules\EIdentity\Http\Controllers\API;


use App\Http\Controllers\Controller;
use Modules\EIdentity\Http\Requests\Auth\LoginRequest;
use Modules\EIdentity\Http\Requests\Auth\ResendOtpRequest;
use Modules\EIdentity\Http\Requests\Auth\OtpVerificationRequest;
use Modules\EIdentity\Http\Requests\Auth\PasswordChangeRequest;
use Modules\EIdentity\Entities\Employees;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    /**
     * Handle an incoming api authentication request.
     *
     * @param LoginRequest $request
     * @return JsonResponse
     */
    public function login(LoginRequest $request): JsonResponse
    {


        // TODO implement rate limiter
        $credentials = $request->only('cnic', 'password');
        $token = Auth::guard('eidentity_api')->attempt($credentials);

        if (!$token) {
            return response()->json([
                'response' => false,
                'errors' => [__('auth.failed')]
            ], 401);
        }
        $user = Auth::guard('eidentity_api')->user();
        return $this->generateToken($user, $token);
    }

    /**
     * Generate login token for user.
     *
     * @param User $user
     * @return JsonResponse
     */
    private function generateToken(Employees $user, $token = null): JsonResponse
    {
        // Revoke previously generated tokens
        $user->tokens()->delete();
        $user->access_token = $token;
        $user->user_id = $user->id;
        return response()->json([
            'response' => true,
            'data' => $user,
        ]);
    }


    /**
     * Logout user.
     *
     * @return JsonResponse
     */


    public function logout()
    {
        Auth::guard('vms_api')->logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    // Resend Verficiation Code 
    public function sendResetCode(ResendOtpRequest $request): JsonResponse
    {
        $employee = Employees::where('cnic', $request->cnic)->first();
        if (!$employee) {
            return sendError("Employee record not found!", [], 403);
        }
        //generate OTP
        $otp = rand(1000, 9999);

        //setting Expiray Time 
        $otp_expiry = Carbon::now()->addMinutes(5);

        $employee->otp = $otp;
        $employee->otp_expiration = $otp_expiry;
        $employee->save();

        return sendResponse('', 'Code Sent Successfully');
    }


    // Verify Otp 
    public function otpVerification(OtpVerificationRequest $request): JsonResponse
    {

        $user = Employees::where('cnic', $request->cnic)->first();
        if ($user->otp == $request->otp && $user->otp_expiration > Carbon::now()) {
            $user->otp = null;
            $user->otp_expiration = null;
            $user->save();
            return sendResponse('', 'Code is valid');
        }

        return sendError("Code is expired or invalid!", [], 403);
    }


    /**
     * Change user's password.
     *
     * @param PasswordChangeRequest $request
     * @param PasswordAction $passwordAction
     * @return JsonResponse
     */
    public function changePassword(PasswordChangeRequest $request)
    {
        $status = $this->changePasswordEmployee($request->cnic, $request['old_password'], $request['new_password']);
        if ($status) {
            return sendResponse('', 'Password Change Successfully');
        }
        return sendError("Failed to change Password!", [], 403);
    }


    public function changePasswordEmployee($cnic, $oldPassword, $newPassword): bool
    {
        $user = Employees::where('cnic', $cnic)->first();
        if (Hash::check($oldPassword, $user->password)) {
            $user->password = Hash::make($newPassword);
            $user->save();
            return true;
        }

        return false;
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::guard('eidentity_api')->user(),
            'authorisation' => [
                'token' => Auth::guard('eidentity_api')->refresh(),
                'type' => 'bearer',
            ]
        ]);
    }
}
