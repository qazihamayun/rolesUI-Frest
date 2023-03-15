<?php

namespace Modules\Vms\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Modules\Vms\Entities\VisitorRegistration;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers;
    protected $registerView = 'vms::auth.register';


    /**
     * Where to redirect users after registration.
     *
     * @var string
     */
    // protected $redirectTo = RouteServiceProvider::HOME;
    protected $redirectTo = 'vms/visitor/dashboard';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }

    public function showRegistrationForm()
    {
        return view('vms::auth.register');
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => ['required', 'string', 'max:255'],
            'cnic' => ['required', 'string', 'max:255', 'unique:vms.users'],
            'mobile' => ['required', 'max:11',],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\Models\User
     */
    protected function create(array $data)
    {
        $user = VisitorRegistration::create([
            'name' => $data['name'],
            'email' => $data['cnic'],
            'cnic' => $data['cnic'],
            'mobile' => $data['mobile'],
            'password' => Hash::make($data['password']),
            'type' => 'visitor',
        ]);
        // $user->assignRole('visitor');
        if (array_key_exists("profile", $data)) {
            if (!empty($data['profile'])) {
                $user->addMediaFromBase64($data['profile'])->usingFileName('user_profile_' . time() . '.png')->toMediaCollection('user_profile');
            }
        }
        if (array_key_exists("cnic_front", $data)) {
            if (!empty($data['cnic_front'])) {
                $user->addMediaFromBase64($data['cnic_front'])->usingFileName('cnic_front_' . time() . '.png')->toMediaCollection('cnic_front');
            }
        }
        if (array_key_exists("cnic_back", $data)) {
            if (!empty($data['cnic_back'])) {
                $user->addMediaFromBase64($data['cnic_back'])->usingFileName('cnic_back_' . time() . '.png')->toMediaCollection('cnic_back');
            }
        }
        return $user;
    }
}
