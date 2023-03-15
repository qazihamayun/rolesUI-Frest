@extends('layouts.' . config('vms.active_layout'))
@php $app_id = config('vms.app_id') @endphp

@section('title', 'Visitor Reports')

@section('content')
    <style>
        .styleabc {
            overflow: auto;
            height: 190px !important;
        }
    </style>
    <!--  Navbar Starts / Breadcrumb Area  -->

    <!-- Traffic sources -->
    <div class="row">
        <!-- Gamification Card -->
        <div class="col-md-6 col-lg-4 mb-4 order-0">
            <div class="card ">

                <div class="card-body">
                    <form method="GET">
                        <div class="from-group">
                            <label class="text-black">From Date</label>
                            <input type="date" name="from_date" class="form-control" value="{{ $from }}" />
                        </div>
                        <div class="from-group">
                            <label class="text-black">To Date</label>
                            <input type="date" name="to_date" class="form-control" value="{{ $to }}" />
                        </div>

                        <div class="from-group pt-3 row">
                            <div class="row">
                                <div class="col-md-6">
                                    <button class="btn btn-sm btn-primary">Filter</button>

                                </div>

                                <div class="col-md-6">
                                    <div class="d-flex flex-row-reverse">

                                        <a href="{{ route('reports.visitors') }}" class="btn btn-sm btn-danger">clear</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <!--/ Gamification Card -->

        <!-- Total Visitor -->
        <div class="col-md-6 col-lg-4 col-xl-4 mb-4 order-0">
            <div class="card">
                <div class="card-header d-flex align-items-center justify-content-between">
                    <h5 class="card-title mb-0">Total Visitor</h5>
                </div>
                <div class="card-body  " style=" height:171px;">

                    <h3> {{ $total }}</h3>

                </div>
            </div>
        </div>
        <!--/ Latest Update -->

        <!-- History -->
        <div class="col-md-6 col-lg-4 col-xl-4 mb-4 order-0">
            <div class="card">
                <div class="card-header d-flex align-items-center justify-content-between">
                    <h5 class="card-title m-0 me-2">
                    </h5>
                </div>
                <div class="card-body styleabc">
                    <div class="customer-issues ">
                        @foreach ($gates as $key => $gate)
                            <div class="customer-issue-list ">
                                <div class="customer-issue-details">
                                    <div class="customer-issues-info">
                                        <h6 class="mb-2 font-12 text-secondary"> {{ $gate->name }}
                                        </h6>
                                        <p class="issues-count mb-2 font-12 text-secondary">
                                            {{ $gate->visitors_count }}
                                        </p>
                                    </div>
                                    <div class="customer-issues-stats">
                                        <div class="progress">
                                            <div class="progress-bar {{ colorGradient(rand(0, 3)) }} position-relative"
                                                role="progressbar"
                                                style="width: {{ getPert($total, $gate->visitors_count) }}%"
                                                aria-valuenow="{{ getPert($total, $gate->visitors_count) }}"
                                                aria-valuemin="0" aria-valuemax="{{ $total }}">
                                                <span class="secondary"></span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        @endforeach

                    </div>
                </div>
            </div>
        </div>
        <!--/ History -->

    </div>


    <div class="card">
        <div class="card-header header-elements-inline">
            <h4 class="table-header">{{ __('Department Vise Report') }}</h4>

        </div>

        <div class="card-body">
            <div class="widget-content widget-content-area br-6">


                <div class="table-responsive mb-4">
                    <table id="last-page-dt" class="table table-hover" style="width:100%">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Title</th>
                                <th>Total Visitor</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach ($departments as $key => $dep)
                                <tr>
                                    <td>{{ ++$key }}</td>
                                    <td>{{ $dep->title }}</td>
                                    <td>{{ $dep->visitors_count }}</td>
                                </tr>
                            @endforeach
                        </tbody>

                    </table>
                </div>
            </div>
        </div>


    </div>
    <!-- Main Body Ends -->
@endsection

@push('plugin-scripts')
    {!! Html::script('assets/js/loader.js') !!}
    {!! Html::script('plugins/table/datatable/datatables.js') !!}
    {!! Html::script('plugins/apex/apexcharts.min.js') !!}
    {!! Html::script('plugins/flatpickr/flatpickr.js') !!}
    {!! Html::script('assets/js/dashboard/dashboard_1.js') !!}
@endpush

@push('custom-scripts')
    <script>
        $(document).ready(function() {
            $('#last-page-dt').DataTable();
        });
    </script>
@endpush
