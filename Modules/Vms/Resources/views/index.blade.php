@extends('layouts.' . config('vms.active_layout'))
@php $app_id = config('vms.app_id') @endphp


@push('stylesheets')
<link rel="stylesheet" href="{{ asset('assets/vendor/libs/apex-charts/apex-charts.css') }}" />
<link rel="stylesheet" href="{{ asset('assets/vendor/libs/datatables-bs5/datatables.bootstrap5.css') }}" />
<link rel="stylesheet" href="{{ asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.css') }}" />
@endpush




@section('content')
<div class="row">
    <!-- Gamification Card -->
    <div class="col-lg-4 col-md-6 col-12 mb-4">
        <div class="card h-100">
            <div class="card-header">
                <h3 class="card-title mb-2">Total Visitors!</h3>
                <!-- <span class="d-block mb-4 text-nowrap">Best seller of the month</span> -->
            </div>
            <div class="card-body">
                <div class="row align-items-end">
                    <div class="col-6">
                        <h1 class="display-6 text-primary mb-2 pt-4 pb-1">{{ $total }}</h1>
                        <!-- <small class="d-block mb-3">You have done 57.6% <br>more sales today.</small>

                                                                                                                                                                                                                                                                                <a href="javascript:;" class="btn btn-sm btn-primary">APP</a> -->
                    </div>
                    <!-- <div class="col-6">
                                                                                                                                                                                                                                                                                <img src="" width="140" height="150" class="rounded-start" alt="View Sales" data-app-light-img="illustrations/prize-light.png" data-app-dark-img="illustrations/prize-dark.png">
                                                                                                                                                                                                                                                                            </div> -->
                </div>
            </div>
        </div>
    </div>
    <!--/ Gamification Card -->

    <!-- Multi Radial Chart -->
    <div class="col-lg-4 col-md-6 col-12 mb-4">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">Visits of {{ \Carbon\Carbon::now()->format('Y') }}</h5>

            </div>
            <div class="card-body">
                <div id="visitsRadialChart"></div>
            </div>
        </div>
    </div>
    <!--/ Multi Radial Chart -->

    <!-- Statistics cards & Revenue Growth Chart -->
    <div class="col-lg-4 col-12">
        <div class="row">
            <!-- Statistics Cards -->
            <div class="col-6 col-md-3 col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <div class="avatar mx-auto mb-2">
                            <span class="avatar-initial rounded-circle bg-label-success"><i class="bx bx-user-check fs-4"></i></span>
                        </div>
                        <span class="d-block text-nowrap">Approved</span>
                        <h2 class="mb-0">{{ $accept + $visited }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-6 col-md-3 col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <div class="avatar mx-auto mb-2">
                            <span class="avatar-initial rounded-circle bg-label-danger"><i class="bx bx-x-circle fs-4"></i></span>
                        </div>
                        <span class="d-block text-nowrap">Re schedule</span>
                        <h2 class="mb-0">{{ $reject }}</h2>
                    </div>
                </div>
            </div>
            <!--/ Statistics Cards -->
            <!-- Revenue Growth Chart -->
            <div class="col-12 col-md-6 col-lg-12 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center pb-0">
                        <h5 class="card-title mb-1">Visitor Requests </h5>
                        <span class="avatar-initial"><i class="fa-brands fa-stack-overflow fa-3x"></i></span>
                    </div>
                    <div class="card-body pb-0">
                        <div id="revenueGrowthChart">
                        </div>
                        <h4 class="text-center">{{ $requested }}</h4>

                    </div>
                </div>
            </div>
            <!--/ Revenue Growth Chart -->
        </div>
    </div>
    <!--/ Statistics cards & Revenue Growth Chart -->

    <!-- Weekly Order Summary -->

    <!--/ Weekly Order Summary -->


    <!-- Marketing Campaigns -->
    <div class="col-xl-12">
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">Visitor List</h5>
                <div class="dropdown">
                    <button class="btn p-0" type="button" id="marketingOptions" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <i class="bx bx-dots-vertical-rounded"></i>
                    </button>
                    <div class="dropdown-menu dropdown-menu-end" aria-labelledby="marketingOptions">
                        <a class="dropdown-item" href="javascript:void(0);">Select All</a>
                        <a class="dropdown-item" href="javascript:void(0);">Refresh</a>
                        <a class="dropdown-item" href="javascript:void(0);">Share</a>
                    </div>
                </div>
            </div>
            <div class="card-body">
                <!-- <div class="d-flex align-items-center justify-content-between flex-wrap gap-3">                                                                                                                                                                                                                                                      </div> -->
            </div>
            <div class="table-responsive p-2">
                <table class="table border-top" id="last-page-dt">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>CNIC</th>
                            <th>Visit To</th>
                            <th>Purpose</th>
                            <th>Date</th>
                            <th>Time</th>


                            <th width="23%">Action</th>
                        </tr>
                    </thead>
                    <tbody class="table-border-bottom-0">
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <!--/ Marketing Campaigns -->
</div>
<!--/ Marketing Campaigns -->
</div>

@extends('vms::visitor/modal');
@endsection

@push('scripts')
<script src="{{ asset('assets/vendor/libs/apex-charts/apexcharts.js') }}"></script>
<!-- <script src="{{ asset('assets/js/dashboards-ecommerce.js') }}"></script> -->

<script src="{{ asset('assets/vendor/libs/datatables/jquery.dataTables.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-bs5/datatables-bootstrap5.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-responsive/datatables.responsive.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/moment/moment.js') }}"></script>

<script>
    $(document).ready(function() {

        $('#last-page-dt').DataTable({
            "pagingType": "full_numbers",
            "lengthMenu": [7, 14, 21, 28],
            "pageLength": 7,
            "ajax": "{{ route('visitors.index') }}?status=2",
            "processing": true,
            "serverSide": true,
            "columns": [

                {
                    data: 'user',
                    name: 'user.name',
                    orderable: false,
                    render: function(data, type, row) {
                        let profile = "";
                        if (data?.profile_image_url) {
                            profile = '<img src="' + data?.profile_image_url +
                                '" class = "me-3 rounded" width = "40"  alt = "' + data?.name +
                                '" >';
                        }
                        return profile + '' + data?.name;
                    }
                },

                {
                    data: 'user.cnic',
                    orderable: false,
                },


                {
                    data: 'visit_to_name',
                    orderable: false,
                    searchable: false,
                },
                {
                    data: 'purpose',
                    orderable: false,
                },
                {
                    data: 'visiting_date',
                    orderable: false,
                },
                {
                    data: 'visiting_time',
                    orderable: false,
                    render: function(data, type, row) {
                        return moment().format('hh:mm a');
                    }
                },




                {
                    data: null,
                    orderable: false,
                    searchable: false,
                    render: function(data, type, row) {
                        let viewButton =
                            `<button class ="btn btn-warning btn-sm showDetails"  data-model=` +
                            encodeURIComponent(JSON.stringify(data)) +
                            `><i class="bx bx-user"></i></button>`;
                        let approveButton = data.status != 3 ?
                            `<button class ="btn btn-success btn-sm accept_visitor"  data-id=` +
                            data.id + `><i class="bx bx-check"></i></button>` : '';
                        let rescheduleButton = data.status != 3 ?
                            `<button class ="btn btn-primary btn-sm modalAction"  data-model=` +
                            encodeURIComponent(JSON.stringify(data)) +
                            `><i class="bx bx-stopwatch"></i></button>` : '';
                        return viewButton + approveButton + rescheduleButton;
                    }
                }

            ],



        });





    });

    // dashboard script 

    /**
     * eCommerce Dashboard
     */

    'use strict';
    (function() {
        let cardColor, headingColor, axisColor, borderColor, shadeColor;

        if (isDarkStyle) {
            cardColor = config.colors_dark.cardColor;
            headingColor = config.colors_dark.headingColor;
            axisColor = config.colors_dark.axisColor;
            borderColor = config.colors_dark.borderColor;
            shadeColor = 'dark';
        } else {
            cardColor = config.colors.white;
            headingColor = config.colors.headingColor;
            axisColor = config.colors.axisColor;
            borderColor = config.colors.borderColor;
            shadeColor = 'light';
        }

        // Visits - Multi Radial Bar Chart
        // --------------------------------------------------------------------

        let visitor_data = JSON.parse('{!! json_encode($current_year_data) !!}');
        const visitsRadialChartEl = document.querySelector('#visitsRadialChart'),
            visitsRadialChartConfig = {
                chart: {
                    height: 270,
                    type: 'radialBar',

                },
                colors: [config.colors.primary, config.colors.danger, config.colors.warning],
                series: [visitor_data?.source_WEB, visitor_data?.source_API, visitor_data?.source_CallCenter],
                plotOptions: {
                    radialBar: {
                        offsetY: -10,
                        hollow: {
                            size: '45%'
                        },
                        track: {
                            margin: 10,
                            background: cardColor
                        },
                        dataLabels: {
                            name: {
                                fontSize: '15px',
                                colors: [config.colors.secondary],
                                fontFamily: 'IBM Plex Sans',
                                offsetY: 25,
                                formatter: function(value) {
                                    return value.toString();
                                }
                            },
                            value: {
                                fontSize: '2rem',
                                fontFamily: 'Rubik',
                                fontWeight: 500,
                                color: headingColor,
                                offsetY: -15,
                                formatter: function(value) {
                                    return value.toString();
                                }
                            },

                            total: {
                                show: true,
                                label: 'Total Visits',
                                fontSize: '15px',
                                fontWeight: 400,
                                fontFamily: 'IBM Plex Sans',
                                color: config.colors.secondary,
                                formatter: function(value, opt) {
                                    // console.log(value);
                                    return "Visitor";
                                }
                            }
                        }
                    }
                },
                grid: {
                    padding: {
                        top: -10,
                        bottom: -10
                    }
                },
                stroke: {
                    lineCap: 'square'
                },
                labels: ['On Spot', 'Mobile', 'Call Center'],
                legend: {
                    show: true,
                    position: 'bottom',
                    horizontalAlign: 'center',
                    labels: {
                        colors: axisColor,
                        useSeriesColors: false,
                    },
                    itemMargin: {
                        horizontal: 15
                    },
                    markers: {
                        width: 10,
                        height: 10,
                        offsetX: -3
                    }
                }
            };

        if (typeof visitsRadialChartEl !== undefined && visitsRadialChartEl !== null) {
            const visitsRadialChart = new ApexCharts(visitsRadialChartEl, visitsRadialChartConfig);
            visitsRadialChart.render();
        }

    })();
</script>
@endpush