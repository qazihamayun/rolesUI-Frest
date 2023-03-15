@extends('layouts.' . config('vms.active_layout'))
@php $app_id = config('vms.app_id') @endphp


@section('content')

<div>
    <!--  Navbar Ends / Breadcrumb Area  -->
    <!-- Main Body Starts -->
    <div class="col-xl-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">{{ __('E Pass  Visitor') }}</h5>

                <div class="dropdown">
                    <a href="{{ route('visitors.index') }}" class="btn btn-primary">Back</a>
                </div>
            </div>
            <div class="card-body">
                <form action="{{ route('epass.visitors.update') }}">
                    <div class="row mt-2">

                        <div class=" col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">
                                <label>Visitor Id: </label>

                                <input type="text" name="visitor_id" class="form-control" placeholder="Enter Visitor ID" id="idField" />
                            </div>
                        </div>
                        <div class=" col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">
                                <label>Name: </label>

                                <input type="text" name="visitor_name" class="form-control" placeholder="User Name" id="visitor_name" />
                                <input type="hidden" name="user_id" class="form-control" placeholder="User Id" id="user_id" />

                            </div>
                        </div>
                        <div class=" col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">
                                <label>Department: </label>

                                <input type="text" id="department_name" placeholder="Department" class="form-control" name="department_name" value="">
                                <input type="hidden" id="department_id" name="department_id" value="">

                            </div>
                        </div>
                        <div class=" col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">
                                <label>Vehicle Reg no: </label>

                                <input type="text" id="vechical_no" placeholder="Vehicle  Reg no" class="form-control" name="vechical_no" value="">

                            </div>
                        </div>

                        <div class=" col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">
                                <label>License no: </label>

                                <input type="text" id="license_no" placeholder="License no" class="form-control" name="license_no" value="">

                            </div>
                        </div>
                        <div class=" col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">
                                <label>Passenger: </label>

                                <input type="text" id="passenger" placeholder="passenger" class="form-control" name="passenger" value="">


                            </div>
                        </div>
                        <div class=" col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">
                                <label>Source: </label>

                                <input type="text" id="source" placeholder="Source" class="form-control" name="source" value="">


                            </div>
                        </div>
                        <div class="col-xs-12 col-sm-12 col-md-6">
                            <div class="form-group">

                                <label>Gate: </label>
                                <select class="select2-multiple  form-control" required name="gate_id">
                                    <option value=""> Select Gate</option>
                                    @foreach ($gate as $value)
                                    <option value="{{ $value->id }}">
                                        {{ $value->name }}
                                    </option>
                                    @endforeach
                                </select>
                            </div>
                        </div>

                        <div class="col-xs-12 col-sm-12 col-md-6 ">
                            <div class="cont">

                                <video id="preview" class="form-control" style="width: 300px; height: 200px;"></video>

                            </div>
                        </div>
                        <div class="col-xs-12 col-sm-12 col-md-6 ">

                            <div class="form-group">

                                <div class="qrinput">

                                    <label>Qrcode:</label>
                                    {!! Form::text('qrcode', null, ['placeholder' => 'Qrcode', 'class' => 'form-control qrcode', 'id' => 'qrcode']) !!}
                                </div>
                            </div>



                        </div>

                    </div>

                    <div class="col-xs-12 col-sm-12 col-md-12 pt-2 text-right">
                        <button type="submit" class="btn btn-primary">verify</button>
                    </div>
                </form>


            </div>


        </div>
        <!-- Main Body Ends -->
    </div>
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
@push('scripts')
<!-- <script type="text/javascript" src="{{ asset('assets/vendor/webcamjs/webcam.min.js') }}"></script>
    <script type="text/javascript" src="{{ asset('assets/vendor/instascan/instascan.min.js') }}"></script> -->
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/webcamjs/1.0.26/webcam.min.js"></script>
    <script type="text/javascript" src="https://rawgit.com/schmich/instascan-builds/master/instascan.min.js"></script>
<script>
    $(document).ready(function() {
        $('body').on('change', '#idField', function() {
            var id = $(this).val();
            let url = "{{ url('vms/visitor/info') }}" + '/' + id;
            $.get(url, function(data) {
                //console.log(data?.data);
                // console.info(JSON.stringify(data));
                if (data.success === true) {
                    Object.keys(data.data).forEach(function(key) {
                        // console.log('Key : ' + key + ', Value : ' + data.data[key])
                        $("#" + key).val(data.data[key]);
                    })
                } else {
                    Swal.fire('No record found  ')

                }

            })
        });
    });
</script>
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
        var visitor_id = $('#idField').val();
        // console.log(visitor_id);
        if (visitor_id == null || visitor_id.length == 0) {
            $('#idField').val(content);
            // document.getElementById('idField').value = content;

        } else {
            $('#qrcode').val(content);

            // document.getElementById('qrcode').value = content;

        }

    });
    Instascan.Camera.getCameras().then(function(cameras) {
        if (cameras.length > 0) {
            // console.log( cameras);
            scanner.start(cameras[0]).then(function() {
                console.log('here');
            }).catch(function(e) {});
        } else {}
    }).catch(function(e) {});

    $(document).ready(function() {
        // Select2 Multiple
        $('.select2-multiple').select2({
            placeholder: "Select",
            allowClear: true
        });

    });
</script>
@endpush