@extends('layouts.'.config('eidentity.active_layout'))
@php $app_id = config('eidentity.app_id') @endphp
@section('content')
    <div class="row">
        <div class="col-12">
            <!-- Traffic sources -->
            <div class="card">
                <div class="card-header header-elements-inline">
                    <h5 class="card-title">{{ $title }}</h5>
                    <div class="header-elements">
                        <div class="form-check form-check-right form-check-switchery form-check-switchery-sm">

                            {{--<label class="form-check-label">
                                Live update:
                                <input type="checkbox" class="form-input-switchery" checked data-fouc>
                            </label>--}}
                        </div>
                    </div>
                </div>

                <div class="card-body">

                    <div class="row">


                        <div class="col-12">


                            {!! Form::model($item, [
                                'enctype' => 'multipart/form-data',
                                'method' => $item->exists ? 'put' : 'post',
                                'route' => $item->exists ? ['eidentity.employee.update', encrypt($item->id)] : ['eidentity.employee.store']
                                ])
                            !!}

                            <h6 class="fw-bold">1. Personal Information</h6>
                            <div class="row g3">
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('title', 'Employee Name ', ['class' => 'form-label req']) !!}
                                        {!! Form::text('employee_name', null, ['class' => 'form-control', 'id' => 'employee_name', 'required' => 'required']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('employee_name') !!}@endif</span>
                                    </div>
                                </div>
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('father_name', 'Father Name ', ['class' => 'form-label req']) !!}
                                        {!! Form::text('father_name', null, ['class' => 'form-control', 'id' => 'father_name', 'required' => 'required']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('father_name') !!}@endif</span>
                                    </div>
                                </div>
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('cnic', 'CNIC# ', ['class' => 'form-label req']) !!}
                                        {!! Form::text('cnic', null, ['class' => 'form-control', 'id' => 'cnic', 'required' => 'required']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('cnic') !!}@endif</span>
                                    </div>
                                </div>
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('mobile_no', 'Mobile# ', ['class' => 'form-label req']) !!}
                                        {!! Form::text('mobile_no', null, ['placeholder'=>'03001234567', 'class' => 'form-control', 'id' => 'mobile_no', 'required' => 'required']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('mobile_no') !!}@endif</span>
                                    </div>
                                </div>
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('dob', 'Date of Birth ', ['class' => 'form-label req']) !!}
                                        {!! Form::date('dob', null, ['class' => 'form-control', 'id' => 'dob', 'required' => 'required']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('dob') !!}@endif</span>
                                    </div>
                                </div>
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('profile_picture', 'Profile Picture', ['class' => 'form-label req']) !!}
                                        {!! Form::file('profile_picture', null,
                                        ['class' => 'form-control', 'id' => 'profile_picture',
                                        "accept"=>"image/png, image/bmp, image/jpeg, image/tiff, image/jpg"
                                        ]) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('profile_picture') !!}@endif</span>
                                    </div>
                                </div>

                                <div class="col-sm-6 col-md-6 col-lg-6 ">
                                    <div class="">
                                        @if($item->exists && !checkNullAndEmpty($item->profile_picture))
                                            <img width="130" src="{{asset("storage/eidentity/$item->profile_picture")}}">
                                        @endif
                                    </div>
                                </div>
                            </div>


                            <br>
                            <h6 class="fw-bold">2. Employment Information</h6>
                            <div class="row g3">
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('date_of_appointment', 'Date of Appointment ', ['class' => 'form-label req']) !!}
                                        {!! Form::date('date_of_appointment', null, ['class' => 'form-control', 'id' => 'date_of_appointment', 'required' => 'required']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('date_of_appointment') !!}@endif</span>
                                    </div>
                                </div>

                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('personnel_no', 'Personnel# ', ['class' => 'form-label req']) !!}
                                        {!! Form::text('personnel_no', null, ['class' => 'form-control', 'id' => 'personnel_no', 'required' => 'required']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('personnel_no') !!}@endif</span>
                                    </div>
                                </div>

                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('designation_id', 'Designation ', ['class' => 'form-label req']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('designation_id') !!}@endif</span>
                                        {!! Form::select('designation_id', $designations,null, ['class' => 'form-control select2', 'id' => 'designation_id', 'required' => 'required']) !!}
                                    </div>
                                </div>

                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('bps_id', 'BPS ', ['class' => 'form-label req']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('bps_id') !!}@endif</span>
                                        {!! Form::select('bps_id', $bps_dd ,null, ['class' => 'form-control select2', 'id' => 'bps_id', 'required' => 'required']) !!}
                                    </div>
                                </div>

                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('employee_category_id', 'Employee Category ', ['class' => 'form-label req']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('employee_category_id') !!}@endif</span>
                                        {!! Form::select('employee_category_id', $employee_category ,null, ['class' => 'form-control select2', 'id' => 'employee_category_id', 'required' => 'required']) !!}
                                    </div>
                                </div>
                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('department_id', 'Department ', ['class' => 'form-label req']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('department_id') !!}@endif</span>
                                        {!! Form::select('department_id', $departments ,null, ['class' => 'form-control select2', 'id' => 'department_id', 'required' => 'required']) !!}
                                    </div>
                                </div>

                                <div class="col-sm-3 col-md-3 col-lg-3 ">
                                    <div class="form-group">
                                        {!! Form::label('guzzeted_id', 'Guzzeted/Non Guzzeted ', ['class' => 'form-label req']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('guzzeted_id') !!}@endif</span>
                                        {!! Form::select('guzzeted_id', $guzzeted_status ,null, ['class' => 'form-control select2', 'id' => 'guzzeted_id', 'required' => 'required']) !!}
                                    </div>
                                </div>

                            </div>

                            <br>
                            <h6 class="fw-bold">3. Reporting Line</h6>
                            <div class="row g3">

                                <div class="col-sm-12 col-md-6 col-lg-6 ">
                                    <div class="form-group">
                                        {!! Form::label('name_of_working_section', 'Name of the Section Currenrly Working ', ['class' => 'form-label req']) !!}
                                        {!! Form::text('name_of_working_section', null, ['class' => 'form-control', 'id' => 'name_of_working_section']) !!}
                                        <span class="help">
                                            Name of the section in which employee is working. For example, Litigation, Budget & Accounts
                                        </span>
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('name_of_working_section') !!}@endif</span>

                                    </div>
                                </div>

                                <div class="col-sm-6 col-md-6 col-lg-6 ">
                                    <div class="form-group">
                                        {!! Form::label('reporting_to_designation_id', 'Reporting to ', ['class' => 'form-label req']) !!}
                                        <span class="help">@if(session()->has('errors')) {!! session('errors')->first('reporting_to_designation_id') !!}@endif</span>
                                        {!! Form::select('reporting_to_designation_id', $designations,null, ['placeholder'=>'Select Designation', 'class' => 'form-control select2', 'id' => 'reporting_to_designation_id']) !!}
                                    </div>
                                </div>
                            </div>

                            <div class="row">
                                <div class="col-12">
                                    <a href="{{ route('eidentity.employee.list') }}" class="btn btn-warning">
                                        <i class="bx bx-arrow-back"></i> Back
                                    </a>
                                    <button type="submit" class="btn btn-success">
                                        <i class="bx bx-save"></i> Save
                                    </button>
                                </div>
                            </div>

                            {!! Form::close() !!}
                        </div>
                    </div>
                </div>
            </div>
            <!-- /traffic sources -->
        </div>
    </div>
@endsection
