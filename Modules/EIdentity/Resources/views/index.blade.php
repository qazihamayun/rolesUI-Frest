@extends('layouts.'.config('settings.active_layout'))
@php $app_id = config('eidentity.app_id') @endphp

@section('content')

    <div class="row">
        <div class="col-12">

            <!-- Traffic sources -->
            <div class="card">
                <div class="card-header header-elements-inline">
                    <h6 class="card-title">{{ $title }}</h6>
                    <div class="header-elements"></div>
                    <div class="text-right" style="text-align: right">
                    </div>
                </div>

                <div class="card-body" style="min-height:500px">
                    @if(auth()->user()->id == 323)
                        <div class="row">
                            <h5>Overall Employees</h5>
                            <div class="col-md-4 col-lg-4 mb-4">
                                <div class="card h-100">
                                    <div class="card-body text-center">
                                        <div class="avatar mx-auto mb-2">
                                        <span class="avatar-initial rounded-circle bg-label-success">
                                            <i class="bx bx-user fs-4"></i>
                                        </span>
                                        </div>
                                        <span class="d-block text-nowrap">Total Employees</span>
                                        <h2 class="mb-0">
                                            <a href="{{route('eidentity.employee.list')}}">
                                                {{$overall_employees_counts['total_employees']??0}}
                                            </a>
                                        </h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 col-lg-4 mb-4">
                                <div class="card h-100">
                                    <div class="card-body text-center">
                                        <div class="avatar mx-auto mb-2">
                                        <span class="avatar-initial rounded-circle bg-label-success">
                                            <i class="bx bx-user-plus fs-4"></i>
                                        </span>
                                        </div>
                                        <span class="d-block text-nowrap">Profile Picture Completed</span>
                                        <h2 class="mb-0">
                                            {{$overall_employees_counts['total_employees_profile_pic_filled']??0}}
                                        </h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 col-lg-4 mb-4">
                                <div class="card h-100">
                                    <div class="card-body text-center">
                                        <div class="avatar mx-auto mb-2">
                                        <span class="avatar-initial rounded-circle bg-label-warning">
                                            <i class="bx bx-user fs-4"></i>
                                        </span>
                                        </div>
                                        <span class="d-block text-nowrap">Profile Picture Pending</span>
                                        <h2 class="mb-0">
                                            {{$overall_employees_counts['total_employees_profile_pic_pending']??0}}
                                        </h2>
                                    </div>
                                </div>
                            </div>
                        </div>
                    @endif
                    <div class="row">
                        <h5>My Own Employees</h5>
                        <div class="col-md-4 col-lg-4 mb-4">
                            <div class="card h-100">
                                <div class="card-body text-center">
                                    <div class="avatar mx-auto mb-2">
                                        <span class="avatar-initial rounded-circle bg-label-success">
                                            <i class="bx bx-user fs-4"></i>
                                        </span>
                                    </div>
                                    <span class="d-block text-nowrap">Total Employees</span>
                                    <h2 class="mb-0">
                                        <a href="{{route('eidentity.employee.list')}}">{{$total_employees??0}}</a>

                                    </h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4 col-lg-4 mb-4">
                            <div class="card h-100">
                                <div class="card-body text-center">
                                    <div class="avatar mx-auto mb-2">
                                        <span class="avatar-initial rounded-circle bg-label-success">
                                            <i class="bx bx-user-plus fs-4"></i>
                                        </span>
                                    </div>
                                    <span class="d-block text-nowrap">Total Record Updated</span>
                                    <h2 class="mb-0">{{$total_update??0}}</h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4 col-lg-4 mb-4">
                            <div class="card h-100">
                                <div class="card-body text-center">
                                    <div class="avatar mx-auto mb-2">
                                        <span class="avatar-initial rounded-circle bg-label-warning">
                                            <i class="bx bx-user fs-4"></i>
                                        </span>
                                    </div>
                                    <span class="d-block text-nowrap">Total Record Pending</span>
                                    <h2 class="mb-0">{{$total_pending??0}}</h2>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
            <!-- /traffic sources -->
        </div>
    </div>

@endsection
