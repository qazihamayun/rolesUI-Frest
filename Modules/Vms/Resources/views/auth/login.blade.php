@extends('layout.master-auth')

@push('plugin-styles')
    {!! Html::style('assets/css/loader.css') !!}
    {!! Html::style('assets/css/authentication/auth_3.css') !!}
@endpush
@section('title', 'Login')

@push('plugin-styles')
    <style>
        .transparent_div {
            padding: 30px 20px;
            background: rgba(255, 255, 255, 0.37);
            border-radius: 10px;
            box-shadow: rgba(0, 0, 0, 0.16) 0px 1px 4px;
            backdrop-filter: blur(1.9px);
            -webkit-backdrop-filter: blur(1.9px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .img_shadow {
            box-shadow: rgba(0, 0, 0, 0.16) 0px 1px 4px;
            padding: 20px;
            border-radius: 10px;
        }

        .main_div_for_login {
            padding: 30px 0;
            width: 80%;
            margin: 0 auto;
            display: flex;
            justify-content: center;
            align-items: center;
            flex-direction: column
        }
    </style>
@endpush

@section('content')

    <!-- Main Body Starts -->
    <div class="login-three">
        <div class="container-fluid login-three-container">
            <div class="main_div_for_login">
                <div class="transparent_div">
                    <div class="row">
                        <div class="col-xl-12 col-lg-12 col-md-12">
                            <div class="row">
                                <div class="col-md-4 mx-auto">
                                    {{-- <h4 class="d-flex justify-content-center"><strong>{{ __('Login') }}</strong></h4> --}}
                                    <img src="{{ asset('assets/img/login.png') }}" class="img-fluid img_shadow" class="mt-3"
                                        alt="">
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-8 mx-auto">

                                    <form method="POST" action="{{ route('login') }}">
                                        @csrf
                                        <div class="login-three-inputs mt-5">
                                            <input type="text" class="form-control @error('email') is-invalid @enderror"
                                                name="email" value="{{ old('email') }}" required autocomplete="email"
                                                placeholder="{{ __('Username') }}">
                                            <i class="las la-user-alt"></i>
                                            @error('email')
                                                <span class="invalid-feedback" role="alert">
                                                    <strong>{{ $message }}</strong>
                                                </span>
                                            @enderror
                                        </div>
                                        <div class="login-three-inputs mt-3">
                                            <input name="password" type="password"
                                                class="form-control @error('password') is-invalid @enderror" required
                                                placeholder="{{ __('Password') }}">
                                            <i class="las la-lock"></i>
                                            @error('password')
                                                <span class="invalid-feedback" role="alert">
                                                    <strong>{{ $message }}</strong>
                                                </span>
                                            @enderror
                                        </div>
                                        <div class="d-flex align-items-center justify-content-between my-3">
                                            <div class="check">
                                                <input class="inp-cbx" id="cbx" type="checkbox" style="display: none">
                                                <label class="cbx" for="cbx">
                                                    <span>
                                                        <svg width="12px" height="10px" viewBox="0 0 12 10">
                                                            <polyline points="1.5 6 4.5 9 10.5 1"></polyline>
                                                        </svg>
                                                    </span>
                                                    <span class="font-13 text-muted">{{ __('Remember me ?') }}</span>
                                                </label>
                                            </div>
                                            <a class="font-13 text-primary"
                                                href="{{ url('/authentications/style3/forgot-password') }}">{{ __('Forgot your Password ?') }}</a>
                                        </div>
                                        <div class="row">
                                            <div class="col-md-12">
                                                <button class="text-white btn bg-gradient-primary btn-block" type="submit">
                                                    {{ __('Login') }} <i class="las la-key ml-2"></i></button>
                                                <a class="font-13 text-primary"
                                                    href="{{ route('register') }}">{{ __('Don`t have an account Sign Up  ?') }}</a>

                                            </div>
                                        </div>
                                    </form>
                                </div>
                            </div>



                        </div>
                    </div>

                </div>
                <div class="row mt-4">
                    <div class="col-md-8">
                        <img src="{{ asset('assets/img/kpitb.png') }}" class="img-fluid ml-3" alt="">

                    </div>
                </div>

            </div>
        </div>
    </div>
    </div>
    <!-- Main Body Ends -->
@endsection

@push('plugin-scripts')
    {!! Html::script('assets/js/loader.js') !!}
    {!! Html::script('assets/js/libs/jquery-3.6.0.min.js') !!}
    {!! Html::script('plugins/bootstrap/js/bootstrap.min.js') !!}
    {!! Html::script('assets/js/authentication/auth_2.js') !!}
@endpush

@push('custom-scripts')
@endpush
