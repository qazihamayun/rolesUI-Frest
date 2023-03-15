<!DOCTYPE html>

<html lang="en" class="light-style customizer-hide" dir="ltr" data-theme="theme-default" data-assets-path="{{ asset('assets/') }}" data-template="horizontal-menu-template">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, minimum-scale=1.0, maximum-scale=1.0" />

    <title>{{ env('APP_NAME') }}</title>
    <meta name="description" content="" />
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="{{ asset('assets/img/favicon/favicon.ico') }}" />
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,300;1,400;1,500;1,600;1,700&family=Rubik:ital,wght@0,300;0,400;0,500;0,600;0,700;1,300;1,400;1,500;1,600;1,700&display=swap" rel="stylesheet" />

    <!-- Icons -->
    <link rel="stylesheet" href="{{ asset('assets/vendor/fonts/boxicons.css') }}" />
    <link rel="stylesheet" href="{{ asset('assets/vendor/fonts/fontawesome.css') }}" />
    <link rel="stylesheet" href="{{ asset('assets/vendor/fonts/flag-icons.css') }}" />

    <!-- Core CSS -->
    <link rel="stylesheet" href="{{ asset('assets/vendor/css/rtl/core.css') }}" class="template-customizer-core-css" />
    <link rel="stylesheet" href="{{ asset('assets/vendor/css/rtl/theme-default.css') }}" class="template-customizer-theme-css" />
    <link rel="stylesheet" href="{{ asset('assets/css/demo.css') }}" />

    <!-- Vendors CSS -->
    <link rel="stylesheet" href="{{ asset('assets/vendor/libs/perfect-scrollbar/perfect-scrollbar.css') }}" />
    <link rel="stylesheet" href="{{ asset('assets/vendor/libs/typeahead-js/typeahead.css') }}" />
    <!-- Vendor -->
    <link rel="stylesheet" href="{{ asset('assets/vendor/libs/formvalidation/dist/css/formValidation.min.css') }}" />

    <!-- Page CSS -->
    <!-- Page -->
    <link rel="stylesheet" href="{{ asset('assets/vendor/css/pages/page-auth.css') }}" />
    <link rel="stylesheet" href="{{ asset('assets/css/my_custom.css') }}" />

    <!-- Helpers -->
    <script src="{{ asset('assets/vendor/js/helpers.js') }}"></script>

    <!--! Template customizer & Theme config files MUST be included after core stylesheets and helpers.js in the <head> section -->
    <!--? Template customizer: To hide customizer set displayCustomizer value false in config.js.  -->
    <script src="{{ asset('assets/vendor/js/template-customizer.js') }}"></script>
    <!--? Config:  Mandatory theme config file contain global vars & default theme options, Set your preferred theme option in this file.  -->
    <script src="{{ asset('assets/js/config.js') }}"></script>
</head>

<body>
    <!-- Content -->

    <div class="authentication-wrapper authentication-cover">
        <div class="authentication-inner row m-0">

            <!-- Left Text -->
            <div class="d-none d-lg-flex col-lg-4 align-items-center justify-content-end p-5 pe-0">
                <div class="w-px-400">
                    <img src="" class="img-fluid scaleX-n1-rtl" alt="multi-steps" width="600" data-app-light-img="illustrations/create-account-light.png" data-app-dark-img="illustrations/create-account-dark.png">
                </div>
            </div>
            <!-- /Left Text -->

            <!--  Multi Steps Registration -->
            <div class="d-flex col-lg-8 authentication-bg p-sm-5 p-3 justify-content-center">
                <div class="d-flex flex-column w-px-700">
                    <!-- Logo -->


                    <div class="app-brand justify-content-center">
                        <a href="/" class="app-brand-link gap-2">
                            <span class="app-brand-text demo h3 mb-0 fw-bold">
                                <img src="{{asset('assets/img/vms_logo.png')}}" width="230">
                            </span>
                        </a>
                    </div>
                    <!-- /Logo -->

                    <div class="my-auto">
                        <div class="main_div_for_register">
                            <div class="transparent_div">

                                <form method="POST" action="{{ route('visitor.register') }}">
                                    @csrf
                                    <div class="row">
                                        <div class="col-md-3 mx-auto my-3">
                                            <img src="{{ asset('assets/img/cardimg.png') }}" class="img-fluid" alt="">
                                        </div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-12">
                                            <div class="row mb-3">

                                                <div class="col-md-6">
                                                    <strong>Full name</strong>

                                                    <input id="name" type="text" placeholder="name" class="form-control @error('name') is-invalid @enderror" name="name" value="{{ old('name') }}" required autocomplete="name" autofocus>

                                                    @error('name')
                                                    <span class="invalid-feedback" role="alert">
                                                        <strong>{{ $message }}</strong>
                                                    </span>
                                                    @enderror
                                                </div>

                                                <div class="col-md-6">
                                                    <strong>Cnic #</strong>

                                                    <input id="cnic" type="text" class="form-control @error('cnic') is-invalid @enderror" placeholder="cnic" name="cnic" required autocomplete="new-cnic">

                                                    @error('cnic')
                                                    <span class="invalid-feedback" role="alert">
                                                        <strong>{{ $message }}</strong>
                                                    </span>
                                                    @enderror
                                                </div>
                                            </div>

                                            <div class="row mb-3">
                                                <div class="col-md-6">
                                                    <strong>Mobile</strong>

                                                    <input id="mobile" type="text" class="form-control @error('mobile') is-invalid @enderror" placeholder="phone" name="mobile">

                                                    @error('mobile')
                                                    <span class="invalid-feedback" role="alert">
                                                        <strong>{{ $message }}</strong>
                                                    </span>
                                                    @enderror
                                                </div>
                                                <div class="col-md-6">
                                                    <strong>Password</strong>

                                                    <input id="password" type="password" class="form-control @error('password') is-invalid @enderror" placeholder="password" name="password" required autocomplete="new-password">

                                                    @error('password')
                                                    <span class="invalid-feedback" role="alert">
                                                        <strong>{{ $message }}</strong>
                                                    </span>
                                                    @enderror
                                                </div>
                                            </div>


                                            <div class="row mb-5">
                                                <div class="col-md-12">
                                                    <strong> Confirm Password</strong>

                                                    <input id="password-confirm" type="password" class="form-control" name="password_confirmation" placeholder="Confirm Password" required autocomplete="new-password">
                                                </div>
                                            </div>

                                        </div>


                                    </div>

                                    <div class="row">
                                        <div class="col-xs-6 col-sm-6 col-md-4">
                                            <div id="my_camera"></div>
                                            <input type=button class="btn btn-block bt-sm btn-primary" value="Profile" onClick="take_snapshot()">
                                            <input type="file" name="profile" class="form-control mt-2">
                                            <div id="results"></div>
                                            <input type="hidden" name="profile" id="profile">
                                        </div>

                                        <div class="col-xs-6 col-sm-6 col-md-4">
                                            <div id="my_camera1"></div>
                                            <input type="button" class="btn btn-block bt-sm btn-primary" value="Cnic Front" onClick="take_snapshot1()">
                                            <input type="file" name="cnic_front" class="form-control mt-2">
                                            <div id="results1">
                                            </div>
                                            <input type="hidden" name="cnic_front" id="cnic_front">
                                        </div>

                                        <div class="col-xs-6 coll-sm-6 col-md-4">

                                            <div id="my_camera2"></div>
                                            <input type="button" class="btn btn-block bt-sm btn-primary" value="Cnic Back" onClick="take_snapshot2()">
                                            <input type="file" name="cnic_back" class="form-control mt-2">
                                            <div id="results2">
                                            </div>
                                            <input type="hidden" name="cnic_back" id="cnic_back">
                                        </div>
                                    </div>






                                    <div class="row">
                                        <div class="col-md-4 mx-auto my-5">
                                            <button type="submit" class="btn btn-block btn-primary">
                                                {{ __('Register') }}
                                            </button>
                                        </div>
                                    </div>

                                </form>
                            </div>
                        </div>

                        <footer class="content-footer footer bg-footer-theme mt-4">
                            <div class="container-xxl d-flex flex-wrap justify-content-center py-2 flex-md-row flex-column mb-2 mb-md-0">
                                <div class="mb-2 mb-md-0">
                                    <h3 class="text-center an-initiative-on">An Initiative of</h3>
                                    <img src="{{asset('assets/site-images/logo-bottom.png')}}" width="300" />
                                </div>

                            </div>
                        </footer>
                    </div>
                </div>
            </div>
            <!-- / Multi Steps Registration -->
        </div>
    </div>

    <!-- / Content -->

    <!-- Core JS -->
    <!-- build:js assets/vendor/js/core.js -->
    <script src="{{ asset('assets/vendor/libs/jquery/jquery.js') }}"></script>
    <script src="{{ asset('assets/vendor/libs/popper/popper.js') }}"></script>
    <script src="{{ asset('assets/vendor/js/bootstrap.js') }}"></script>
    <script src="{{ asset('assets/vendor/libs/perfect-scrollbar/perfect-scrollbar.js') }}"></script>

    <script src="{{ asset('assets/vendor/libs/hammer/hammer.js') }}"></script>

    <script src="{{ asset('assets/vendor/libs/i18n/i18n.js') }}"></script>
    <script src="{{ asset('assets/vendor/libs/typeahead-js/typeahead.js') }}"></script>

    <script src="{{ asset('assets/vendor/js/menu.js') }}"></script>
    <!-- endbuild -->

    <!-- Vendors JS -->
    <script src="{{ asset('assets/vendor/libs/formvalidation/dist/js/FormValidation.min.js') }}"></script>
    <script src="{{ asset('assets/vendor/libs/formvalidation/dist/js/plugins/Bootstrap5.min.js') }}"></script>
    <script src="{{ asset('assets/vendor/libs/formvalidation/dist/js/plugins/AutoFocus.min.js') }}"></script>

    <!-- Main JS -->
    <script src="{{ asset('assets/js/main.js') }}"></script>

    <!-- Page JS -->
    <script src="{{ asset('assets/js/pages-auth.js') }}"></script>


    <script type="text/javascript" src="{{ asset('assets/vendor/webcamjs/webcam.min.js') }}"></script>
    <script type="text/javascript" src="{{ asset('assets/vendor/instascan/instascan.min.js') }}"></script>
    <!-- Configure a few settings and attach camera -->
    <script language="JavaScript">
        Webcam.set({
            width: 150,
            height: 150,
            image_format: 'jpg',
            jpeg_quality: 100
        });
        Webcam.attach('#my_camera');
        Webcam.attach('#my_camera1');
        Webcam.attach('#my_camera2');
    </script>
    <!-- A button for taking snaps -->

    <!-- Code to handle taking the snapshot and displaying it locally -->
    <script language="JavaScript">
        function take_snapshot() {

            // take snapshot and get image data
            Webcam.snap(function(data_uri) {
                // display results in page
                document.getElementById('results').innerHTML =
                    '<img src="' + data_uri + '" />';

                $('#profile').val(data_uri);


            });
        }

        function take_snapshot1() {

            // take snapshot and get image data
            Webcam.snap(function(data_uri) {
                // display results in page
                document.getElementById('results1').innerHTML =
                    '<img src="' + data_uri + '"  />';
                $('#cnic_front').val(data_uri);


            });
        }

        function take_snapshot2() {

            // take snapshot and get image data
            Webcam.snap(function(data_uri) {
                // display results in page
                document.getElementById('results2').innerHTML =
                    '<img src="' + data_uri + '" name="cnic_back"/>';

                $('#cnic_back').val(data_uri);

            });
        }
    </script>
</body>

</html>