@extends('layouts.' . config('vms.active_layout'))
@php $app_id = config('vms.app_id') @endphp

@section('content')
    <div class="row">
        <div class="col-12">

            <!-- Traffic sources -->
            <div class="card">
                <div class="card-header header-elements-inline">
                    <h5 class="card-title">{{ $title }}</h5>
                    <div class="header-elements">
                        <div class="form-check form-check-right form-check-switchery form-check-switchery-sm">
                        </div>
                    </div>
                </div>

                <div class="card-body">
                    <div class="row">
                        <div class="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                            <div class="widget-content widget-content-area br-6">

                                {!! Form::open(['route' => 'visitors.store', 'files' => true, 'method' => 'POST']) !!}
                                <div class="row">

                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="form-group">
                                            <label>Name:</label>
                                            {!! Form::text('name', null, ['placeholder' => 'Name', 'class' => 'form-control']) !!}
                                        </div>
                                    </div>

                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="form-group">
                                            <label>Phone:</label>
                                            {!! Form::text('mobile', null, ['placeholder' => 'Phone', 'class' => 'form-control']) !!}
                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="form-group">
                                            <label>CNIC:</label>
                                            {!! Form::text('cnic', null, ['placeholder' => 'CNIC', 'class' => 'form-control']) !!}
                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-6">

                                        <div class="form-group">
                                            <label>Visitor Type :</label>
                                            {!! Form::select('type', ['1' => 'Pedestrian', '2' => 'By Vehicle'], null, [
                                                'class' => 'form-control visitor_type',
                                            ]) !!}
                                        </div>
                                    </div>




                                    <div class="col-xs-12 col-sm-12 col-md-6 Vehicle_option">
                                        <div class="form-group">
                                            <label>Vehicle:</label>
                                            {!! Form::text('vechical_no', null, ['placeholder' => 'Vehicle', 'class' => 'form-control']) !!}
                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-6 Vehicle_option">
                                        <div class="form-group">
                                            <label>Driver License :</label>
                                            {!! Form::text('license_no', null, ['placeholder' => 'License', 'class' => 'form-control']) !!}
                                        </div>
                                    </div>

                                    {{-- number of pessenger in number --}}

                                    <div class="col-xs-12 col-sm-12 col-md-6 Vehicle_option">
                                        <div class="form-group">
                                            <label>Number of Pessenger:</label>
                                            {!! Form::number('passenger', null, ['placeholder' => 'Number of Pessenger', 'class' => 'form-control']) !!}
                                        </div>
                                    </div>

                                    {{-- Vehicle make model --}}

                                    <div class="col-xs-12 col-sm-12 col-md-6 Vehicle_option">
                                        <div class="row">
                                            <div class="col-md-6">
                                                <div class="form-group">
                                                    <label>Vehicle make :</label>
                                                    <select class="select2-multiple  form-control"
                                                        style="width: 100% ;height:45px;" name="vehicle_make">
                                                        <option value="">Select Vehicle make</option>
                                                        @foreach ($vehcilemanufacturer as $value)
                                                            <option value="{{ $value->id }}">{{ $value->name }}
                                                            </option>
                                                        @endforeach
                                                    </select>

                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                <div class="form-group">
                                                    <label>Vehicle model:</label>

                                                    <input type="number" class="form-control " placeholder="YYYY"
                                                        name="vehicle_model" min="1940" max="2020">

                                                </div>
                                            </div>
                                        </div>
                                    </div>


                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="form-group">

                                            <label>Department: </label>
                                            <select class="select2-multiple  form-control" required name="department_id">
                                                multiple="multiple" {{-- <select name="department_id" class="form-control " required>
                                                             --}}
                                                <option value="">Select Department</option>
                                                @foreach ($department as $value)
                                                    <option value="{{ $value->id }}">{{ $value->title }}
                                                    </option>
                                                @endforeach
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-3">
                                        <div class="form-group">

                                            <label>Officer </label>
                                            <select class="select2-multiple  form-control" name="visit_to_id">

                                                <option value="">Select Officer</option>
                                                {{-- @foreach ($user as $value)
                                                    <option value="{{ $value->id }}">{{ $value->title }}
                                                    </option>
                                                @endforeach --}}
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-3">
                                        <div class="form-group">

                                            <label>Gate: </label>
                                            <select class="select2-multiple  form-control" required name="gate_id">
                                                <option value=""> Select Gate</option>
                                                @foreach ($gate as $value)
                                                    <option value="{{ $value->id }}">{{ $value->name }}
                                                    </option>
                                                @endforeach
                                            </select>
                                        </div>
                                    </div>

                                    <div class="col-md-12"></div>

                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="row border m-1">
                                            <div class="col-md-6">
                                                <div class="from-group">
                                                    <div id="my_camera"></div>
                                                    <input type=button class="btn btn-primary btn-sm" value="Profile"
                                                        onClick="take_snapshot()">

                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                <div id="results" style="height: 150px;width:150 !mportant;">
                                                </div>
                                                <input type="hidden" name="profile" id="profile">


                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-xs-12 coll-sm-12 col-md-6">
                                        <div class="row border m-1">
                                            <div class="col-md-6">
                                                <div class="from-group">
                                                    <div id="my_camera1"></div>
                                                    <input type=button class="btn btn-primary btn-sm" value=" Cnic Front"
                                                        onClick="take_snapshot1()">

                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                <div id="results1" style="height: 150px;width:150 !important;">
                                                </div>
                                                <input type="hidden" name="cnic_front" id="cnic_front">

                                            </div>
                                        </div>


                                    </div>
                                    <div class="col-xs-12 coll-sm-12 col-md-6 mb-2">
                                        <div class="row border m-1">
                                            <div class="col-md-6">
                                                <div class="from-group">

                                                    <div id="my_camera2"></div>
                                                    <input type=button class="btn btn-primary btn-sm" value=" Cnic Back"
                                                        onClick="take_snapshot2()">


                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                <div id="results2" style="height: 150px;width:150">
                                                </div>
                                                <input type="hidden" name="cnic_back" id="cnic_back">
                                            </div>
                                        </div>

                                    </div>




                                    <div class="col-xs-12 col-sm-12 col-md-6 ">
                                        <div class="row border m-1">
                                            <video id="preview" style="height: 150px;width:150"></video>
                                            <label>Scane QR Code:</label>
                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-6" style="height:120px">
                                        <div class="form-group">
                                            <div class="qrinput">
                                                <label>Qrcode:</label>
                                                {!! Form::text('qrcode', null, ['placeholder' => 'Qrcode', 'class' => 'form-control qrcode', 'id' => 'qrcode']) !!}
                                            </div>
                                        </div>
                                    </div>




                                    {{-- <div class="col-xs-12 col-sm-12 col-md-12">
                                                <div class="form-group">
                                                    <strong>Role:</strong>
                                                    {!! Form::select('roles[]', $roles, [], ['class' => 'form-control', 'multiple']) !!}
                                                </div>
                                            </div> --}}
                                    <div class="col-xs-12 col-sm-12 col-md-12 text-right">
                                        <button type="submit" class="btn btn-primary">Create</button>
                                    </div>
                                </div>
                                {!! Form::close() !!}


                            </div>
                        </div>
                    </div>
                </div>


            </div>
            <!-- /traffic sources -->

        </div>
    </div>
@endsection

@push('stylesheets')
    <style type="text/css">
        .qrcode {
            font-size: 16px;
            font-weight: bold;
            padding: 4px;
        }

        .select2-container .select2-selection--single {
            height: 40px;
            border: 1px solid #dcdcdc;
            border-radius: 7px;
        }
    </style>
@endpush

@push('scripts')
    <script type="text/javascript" src="{{ asset('assets/vendor/webcamjs/webcam.min.js') }}"></script>
    <script type="text/javascript" src="{{ asset('assets/vendor/instascan/instascan.min.js') }}"></script>
    <script>
        document.querySelector("input[type=number]")
            .oninput = e => console.log(new Date(e.target.valueAsNumber, 0, 1))
    </script>

    <script type="text/javascript">
        let scanner = new Instascan.Scanner({
            video: document.getElementById('preview')
        });
        scanner.addListener('scan', function(content) {
            // console.log(content);
            document.getElementById('qrcode').value = content;
        });
        Instascan.Camera.getCameras().then(function(cameras) {
            if (cameras.length > 0) {
                // console.log( cameras);
                scanner.start(cameras[0]).then(function() {
                    console.log('here');
                }).catch(function(e) {
                    // console.log("exp",e);
                });
            } else {
                // console.error('No cameras found.');
            }
        }).catch(function(e) {
            // console.error(e);
        });
    </script>

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

        $(document).ready(function() {
            $('.Vehicle_option').hide();
            // on visitor type change
            $('.visitor_type').on('change', function() {
                var visitor_type = $(this).val();
                if (visitor_type == 2) {
                    $('.Vehicle_option').show();
                } else {
                    $('.Vehicle_option').hide();
                }
            });
        });
        $(document).ready(function() {
            // Select2 Multiple
            $('.select2-multiple').select2({
                placeholder: "Select",
                allowClear: true
            });

        });
    </script>
@endpush
