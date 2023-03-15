@extends('layouts.' . config('vms.active_layout'))
@php $app_id = config('vms.app_id') @endphp

@section('title', 'Edit Visitor')

@section('content')

    <div>
        <!--  Navbar Starts / Breadcrumb Area  -->
        <div class="sub-header-container">
            <header class="header navbar navbar-expand-sm">
                <a href="javascript:void(0);" class="sidebarCollapse" data-placement="bottom">
                    <i class="las la-bars"></i>
                </a>
                <ul class="navbar-nav flex-row">
                    <li>
                        <div class="page-header">
                            <nav class="breadcrumb-one" aria-label="breadcrumb">
                                <ol class="breadcrumb">
                                    <li class="breadcrumb-item"><a href="javascript:void(0);">{{ __('Visitor') }}</a></li>
                                </ol>
                            </nav>
                        </div>
                    </li>
                </ul>
            </header>
        </div>


        <!--  Navbar Ends / Breadcrumb Area  -->
        <!-- Main Body Starts -->
        <div class="layout-px-spacing">
            <div class="layout-top-spacing mb-2">
                <div class="col-md-12">
                    <div class="row">
                        <div class="container p-0">
                            <div class="row layout-top-spacing date-table-container card">

                                <!-- Datatable go to last page -->
                                <div class="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                                    <div class="widget-content widget-content-area br-6">
                                        <div class="row">
                                            <div class="col-sm-10">
                                                <h4 class="table-header">{{ __('Edit Visitor') }}</h4>
                                            </div>
                                            <div class="col-sm-2 text-right"> <a href="{{ route('visitors.index') }}"
                                                    class="btn btn-primary">Back</a></div>
                                        </div>

                                        {!! Form::model($visitor, ['method' => 'POst', 'route' => ['visitor.info.update', $visitor->id]]) !!}
                                        <div class="row">

                                            <div class="col-xs-12 col-sm-12 col-md-6">
                                                <div class="form-group">
                                                    <label>Name:</label>
                                                    <input type="hidden" name="user_id" value="{{ $visitor->user->id }}">
                                                    {!! Form::text('name', $visitor->user->name, ['placeholder' => 'Name', 'class' => 'form-control']) !!}
                                                </div>
                                            </div>

                                            <div class="col-xs-12 col-sm-12 col-md-6">
                                                <div class="form-group">
                                                    <label>Phone:</label>
                                                    {!! Form::text('mobile', $visitor->user->mobile, ['placeholder' => 'Phone', 'class' => 'form-control']) !!}
                                                </div>
                                            </div>
                                            <div class="col-xs-12 col-sm-12 col-md-6">
                                                <div class="form-group">
                                                    <label>CNIC:</label>
                                                    {!! Form::text('cnic', $visitor->user->cnic, ['placeholder' => 'CNIC', 'class' => 'form-control']) !!}
                                                </div>
                                            </div>



                                            <div class="col-xs-12 col-sm-12 col-md-6">
                                                <div class="form-group">

                                                    <label>Department: </label>
                                                    <select class="select2-multiple  form-control"required
                                                        name="department_id">
                                                        multiple="multiple" {{-- <select name="department_id" class="form-control " required>
                                                             --}}
                                                        <option value="">Select Department</option>
                                                        @foreach ($department as $value)
                                                            <option value="{{ $value->id }}"
                                                                {{ $visitor->department_id == $value->id ? 'selected' : '' }}>
                                                                {{ $value->title }}</option>
                                                        @endforeach
                                                    </select>
                                                </div>
                                            </div>
                                            <div class="col-xs-12 col-sm-12 col-md-6">
                                                <div class="form-group">

                                                    <label>Gate: </label>
                                                    <select class="select2-multiple  form-control" required name="gate_id">
                                                        <option value=""> Select Gate</option>
                                                        @foreach ($gate as $value)
                                                            <option value="{{ $value->id }}"
                                                                {{ $visitor->gate_id == $value->id ? 'selected' : '' }}>
                                                                {{ $value->name }}</option>
                                                        @endforeach
                                                    </select>
                                                </div>
                                            </div>


                                            <div class="col-xs-12 col-sm-12 col-md-6 ">
                                                <div class="cont row  border rounded">
                                                    <video id="preview" style="width: 175px; height: 170px;"></video>
                                                    <label>Scane QR Code:</label>

                                                </div>
                                            </div>
                                            <div class="col-xs-12 col-sm-12 col-md-6 " style="margin-top:-90px">

                                                <div class="form-group">

                                                    <div class="qrinput">

                                                        <label>Qrcode:</label>
                                                        {!! Form::text('qrcode', $visitor->qrcode, [
                                                            'placeholder' => 'Qrcode',
                                                            'class' => 'form-control qrcode',
                                                            'id' => 'qrcode',
                                                        ]) !!}
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
                                                <button type="submit" class="btn btn-primary">Update</button>
                                            </div>
                                        </div>
                                        {!! Form::close() !!}


                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Main Body Ends -->
    </div>
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
@endsection
@section('script')
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>

    <script type="text/javascript" src="{{ asset('webcamjs/webcam.min.js') }}"></script>
    <script type="text/javascript" src="{{ asset('instascan/instascan.min.js') }}"></script>
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
    {{-- <script language="JavaScript">
        Webcam.set({
            width: 150,
            height: 150,
            image_format: 'jpg',
            jpeg_quality: 100
        });
        Webcam.attach('#my_camera');
        Webcam.attach('#my_camera1');
        Webcam.attach('#my_camera2');
    </script> --}}
    <!-- A button for taking snaps -->

    <!-- Code to handle taking the snapshot and displaying it locally -->
    {{-- <script language="JavaScript">
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
    </script> --}}

@endsection
