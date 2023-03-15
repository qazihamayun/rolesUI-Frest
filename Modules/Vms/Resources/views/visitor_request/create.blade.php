@extends('layouts.app_screen_frest_vms')
@php $app_id = config('vms.app_id') @endphp
<link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />

@section('title', 'Create Visitor')
@section('content')

    <div class="row">
        <div class="col-12">

            <!-- Traffic sources -->
            <div class="card">
                <div class="card-header header-elements-inline">
                    <h5 class="card-title mb-0">{{ $title }}</h5>

                    <div class="header-elements">
                        <div class="form-check form-check-right form-check-switchery form-check-switchery-sm">
                        </div>
                    </div>
                </div>

                <div class="card-body">
                    <div class="row">
                        <div class="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                            <div class="widget-content widget-content-area br-6">

                                {!! Form::open(['route' => 'my.store', 'files' => true, 'method' => 'POST']) !!}
                                <div class="row">


                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <strong>Visitor Type :</strong>
                                        <select class="form-control visitor_type" name="type">
                                            <option selected>Select Type</option>
                                            <option value="1">Pedestrain</option>
                                            <option value="2">By Vechical</option>
                                        </select>


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

                                            <label>Department </label>
                                            <select class="select2-multiple  form-control"required name="department_id">
                                                <option value="">Select Department</option>
                                                @foreach ($department as $value)
                                                    <option value="{{ $value->id }}">{{ $value->title }}
                                                    </option>
                                                @endforeach
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="form-group">

                                            <label>purpose </label>
                                            {!! Form::text('purpose', null, ['placeholder' => 'Purpose', 'class' => 'form-control']) !!}

                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="form-group">

                                            <label>Visit Date </label>

                                            <input type="date" class="form-control" id="start" name="visiting_date"
                                                min="2023-02-01">

                                        </div>
                                    </div>
                                    <div class="col-xs-12 col-sm-12 col-md-6">
                                        <div class="form-group">

                                            <label>Visiting Time </label>
                                            <input type="time" class="form-control" name="visiting_time" id="">

                                        </div>
                                    </div>


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
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>



    <script type="text/javascript">
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
