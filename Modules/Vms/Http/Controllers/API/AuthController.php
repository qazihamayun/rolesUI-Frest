<?php


namespace Modules\Vms\Http\Controllers\API;

use App\Actions\OtpAction;
use App\Actions\PasswordAction;
use App\Http\Controllers\Controller;
use Modules\Vms\Http\Requests\Auth\LoginRequest;
use Modules\Vms\Http\Requests\Auth\OtpVerificationRequest;
use Modules\Vms\Http\Requests\Auth\PasswordChangeRequest;
use Modules\Vms\Http\Requests\Auth\RegisterRequest;
use Modules\Vms\Http\Requests\EmailAddressRequest;
// use App\Models\User;
use Modules\Vms\Entities\VisitorRegistration;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Auth;

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
        $credentials = $request->only('email', 'password');
        $token = Auth::guard('vms_api')->attempt($credentials);

        if (!$token) {
            return response()->json([
                'response' => false,
                'errors' => [__('auth.failed')]
            ], 401);
        }
        $user = Auth::guard('vms_api')->user();
        return $this->generateToken($user, $token);
    }

    /**
     * Generate login token for user.
     *
     * @param User $user
     * @return JsonResponse
     */
    private function generateToken(VisitorRegistration $user, $token = null): JsonResponse
    {
        // Revoke previously generated tokens
        $user->tokens()->delete();

        // $user->access_token = $user->createToken('mobile-app')->plainTextToken;
        $user->access_token  = $token;
        $user->user_id = $user->id;
        return response()->json([
            'response' => true,
            'data' => $user,
        ]);
    }

    /**
     * Register a new account.
     *
     * @param RegisterRequest $request
     * @return JsonResponse
     */
    public function register(RegisterRequest $request): JsonResponse
    {



        $user = VisitorRegistration::where('email', $request->cnic)->first();
        if (!$user) {
            $user = VisitorRegistration::create([
                'name' => $request['name'],
                'email' => $request['cnic'],
                'cnic' => $request['cnic'],
                'password' => Hash::make($request['password']),
                'type' => 'visitor',
            ]);

            // $user->assignRole('visitor');

            if ($request->has('user_profile')) {
                if (!empty($request->user_profile)) {
                    $user->addMediaFromBase64($request->user_profile)->usingFileName('user_profile_' . time() . '.png')->toMediaCollection('user_profile');
                }
            }
            if ($request->has('cnic_front')) {
                if (!empty($request->cnic_front)) {
                    $user->addMediaFromBase64($request->cnic_front)->usingFileName('cnic_front_' . time() . '.png')->toMediaCollection('cnic_front');
                }
            }
            if ($request->has('cnic_back')) {
                if (!empty($request->cnic_back)) {
                    $user->addMediaFromBase64($request->cnic_back)->usingFileName('cnic_back_' . time() . '.png')->toMediaCollection('cnic_back');
                }
            }
        } else {
            return sendError("Cnic Number Already Found", [], 401);
        }

        $token = Auth::guard('vms_api')->login($user);
        return $this->generateToken($user, $token);
    }

    /**
     * Verify user's OTP.
     *
     * @param OtpVerificationRequest $request
     * @param OtpAction $otpAction
     * @return JsonResponse
     */
    public function otpVerification(OtpVerificationRequest $request, OtpAction $otpAction): JsonResponse
    {
        if ($otpAction->verifyOtp($request['otp'])) {
            return response()->json();
        } else {
            return response()->json([
                'message' => __('interface.otp-code-invalid')
            ], 422);
        }
    }

    /**
     * Resend the OTP code.
     *
     * @param OtpAction $otpAction
     * @return JsonResponse
     */
    public function otpResend(OtpAction $otpAction): JsonResponse
    {
        if ($otpAction->resetOtp()) {
            return response()->json([
                'message' => __('interface.resent-otp')
            ]);
        } else {
            return response()->json([
                'message' => __('interface.resent-otp-not-allowed'),
                'waiting-time-seconds' => $otpAction->remainingSecondsForResettingOtp()
            ], 422);
        }
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

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::guard('vms_api')->user(),
            'authorisation' => [
                'token' => Auth::guard('vms_api')->refresh(),
                'type' => 'bearer',
            ]
        ]);
    }
    /**
     * Send password reset link to user.
     *
     * @param EmailAddressRequest $request
     * @param PasswordAction $passwordAction
     * @return JsonResponse
     */
    public function sendResetLink(EmailAddressRequest $request, PasswordAction $passwordAction): JsonResponse
    {
        $status = $passwordAction->sendResetLink($request['email']);

        return response()->json($status, $status['status'] === 'success' ? 200 : 422);
    }

    /**
     * Change user's password.
     *
     * @param PasswordChangeRequest $request
     * @param PasswordAction $passwordAction
     * @return JsonResponse
     */
    public function changePassword(PasswordChangeRequest $request, PasswordAction $passwordAction)
    {
        $status = $passwordAction->changePassword($request['old_password'], $request['new_password']);
        if ($status) {
            return $this->logout();
        }
        return response()->json([], Response::HTTP_FORBIDDEN);
    }
}
