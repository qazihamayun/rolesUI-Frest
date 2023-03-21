@push('stylesheets')
    <link rel="stylesheet" href="{{ asset('assets/vendor/libs/animate-css/animate.css') }}" />
    <link rel="stylesheet" href="{{ asset('assets/vendor/libs/sweetalert2/sweetalert2.css') }}" />
@endpush


<!-- Modal -->


<div class="modal" tabindex="-1" id="myModal" role="dialog">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content ">
            <div class="modal-header">
                <h5 class="modal-title" id="exampleModalCenterTitle">Visit Reshudule</h5>

            </div>
            <div class="modal-body">
                <form id="modalSubmit">

                    <div class="form-group" id="">


                        <textarea rows="2" cols="50" class="form-control" placeholder="Enter Comments" name="rejected_reason"></textarea>
                    </div>
                    <input type="hidden" name="id" id="visitor_id" />

                    <div class="form-group ">
                        <input type="time" class="form-control col-md-6 " id="Mtime" name="visiting_time">
                    </div>
                    <div class="form-group" id="">

                        <input type="date" id="visiting_date" class="form-control  " name="visiting_date">
                    </div>



                    <div class="form-group float-right pt-2">
                        <button type="submit" class="btn btn-primary btn-sm">Submit</button>
                        <button type="button" class="btn btn-danger btn-sm" id="Modelcancel">Cancel</button>
                    </div>
                </form>
            </div>


        </div>
    </div>
</div>

<!-- Show Modal  -->
<div class="modal" tabindex="-1" id="DataModal" role="dialog">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content ">
            <div class="modal-header">
                <h5 class="modal-title" id="exampleModalCenterTitle">Visitor Details</h5>

            </div>
            <div class="modal-body">
                <div id="here_table">

                </div>

            </div>

        </div>
    </div>
</div>

<style>
    th {
        margin-bottom: 10 px;
    }
</style>
@push('scripts')
    <script src="{{ asset('assets/vendor/libs/sweetalert2/sweetalert2.js') }}"></script>
    <script src="{{ asset('assets/vendor/libs/moment/moment.js') }}"></script>
    <script>
        $(document).ready(function() {

            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': '{{ csrf_token() }}'
                }
            });


            // perfume and Action 
            $(document).on('click', '.modalAction', function() {
                // getting current Object 
                let modelData = $(this).attr("data-model");
                modelData = JSON.parse(decodeURIComponent(modelData));
                $("#Mtime").val(modelData?.visiting_time);

                // setting Selected Date 
                let visiting_date = moment(modelData?.visiting_date).format('YYYY-MM-DD');
                $('#visiting_date').val(visiting_date);


                $("#visitor_id").val(modelData?.id);

                $("#myModal").modal("show");

            });

            //  End Per action 

            // Action Res 
            $("#modalSubmit").submit(function(e) {
                e.preventDefault();
                let form = $("#modalSubmit");
                let formData = form.serializeArray();
                var token = $('input[name="_token"]').val();

                let visitorid = $("#visitor_id").val();
                // console.log(formData);
                $.ajax({
                    url: `/vms/visitors/${visitorid}`,
                    type: 'PUT',
                     data: formData,
                    headers: {
                        'X-CSRF-Token': token
                    },
                    success: function(response) {
                        if (response.success == true) {
                            Swal.fire({
                                title: "Success",
                                text: response.message,
                                icon: "success",
                                showCancelButton: false,
                                confirmButtonText: "Ok",
                                allowOutsideClick: false,
                            });
                            $("#myModal").modal('hide');
                            $('#last-page-dt').DataTable().ajax.reload();
                        } else {
                            Swal.fire({
                                title: "Error",
                                text: response.message,
                                icon: "error",
                                showCancelButton: false,
                                confirmButtonText: "Ok",
                                allowOutsideClick: false,
                            });
                        }
                    },
                    error: function(response) {
                        Swal.fire({
                            title: "Error",
                            text: response.message,
                            icon: "error",
                            showCancelButton: false,
                            confirmButtonText: "Ok",
                            allowOutsideClick: false,
                        }).then((result) => {
                            if (result.isConfirmed) {
                                location.reload();
                            }
                        });
                    }
                });
            });
            //End of Res


            // Accept Visitor 
            $(document).on('click', '.accept_visitor', function() {
                let this_button = $(this);
                let visitor_id = $(this).attr("data-id");
                Swal.fire({
                    title: 'Are you sure?',
                    text: "You won't be able to revert this!",
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonText: 'Yes, approve it!',
                    customClass: {
                        confirmButton: 'btn btn-primary me-3',
                        cancelButton: 'btn btn-label-secondary'
                    },
                    buttonsStyling: false
                }).then(function(result) {
                    if (result.value) {

                        $.ajax({
                            url: `/vms/visitors/${visitor_id}`,
                            type: 'PUT',
                            data: {
                                status: 3
                            },
                            success: function(response) {
                                if (response.success === true) {
                                    Swal.fire({
                                        icon: 'success',
                                        title: 'Approved!',
                                        text: 'Visitor has been approved.',
                                        customClass: {
                                            confirmButton: 'btn btn-success'
                                        }
                                    });
                                    this_button.remove();
                                }

                            },
                            error: function(response) {

                            }
                        });
                    }
                });
            });

            // Accept Visitor 

            $("#Modelcancel").on('click', function() {
                $("#myModal").modal('hide');
            });


            $(document).on('click', '.showDetails', function() {
                // getting current Object 
                let modelData = $(this).attr("data-model");
                modelData = JSON.parse(decodeURIComponent(modelData));
                $("#name").val(modelData.user.name?.name);
                var img_url = modelData?.user?.profile_image_url ??
                    "https://bootstrapious.com/i/snippets/sn-team/teacher-4.jpg";
                var cnic_back = modelData?.user?.cnic_back_url ??
                    "https://bootstrapious.com/i/snippets/sn-team/teacher-4.jpg";
                var cnic_front = modelData?.user?.cnic_front_url ??
                    "https://bootstrapious.com/i/snippets/sn-team/teacher-4.jpg";
                var content = `
                <div class="row">
                    <div class="col-xl-12">
                        <div class="row">
                            <div class="col-xl-4">
                                <div class="bg-white rounded"><img src="${img_url} "alt="" width="100" class="img-fluid rounded-circle mb-3 img-thumbnail shadow-sm">
                                    <h5 class="mb-0">${modelData?.user?.name}</h5><span class="small text-uppercase text-muted">${ modelData?.user?.cnic}</span>
                                </div>
                                <div class="bg-white"><img src="${cnic_front} "alt="" width="100" class="img-fluid  mb-3 img-thumbnail shadow-sm">
                                </div>
                                <div class="bg-white"><img src="${cnic_back} "alt="" width="100" class="img-fluid  mb-3 img-thumbnail shadow-sm">
                                </div>
                            </div>
                            <div class="col-xl-8">
                                <table class="table table-bordered table-striped">
                                    <tr>
                                        <th>Mobile #</th>
                                        <td>${modelData?.user?.mobile  || 'N/A'}</td>
                                    </tr>

                                    <tr>
                                        <th>Department</th>
                                        <td>${modelData?.department_name  || 'N/A'}</td>
                                    </tr>
                                    <tr><th>Gate</th><td>${ modelData?.gate_name  || 'N/A'}</td></tr>
                                    <tr><th>Vehicle No</th><td>${ modelData?.vechical_no || 'N/A'}</td></tr>
                                    <tr><th>Qrcode</th><td>${ modelData?.qrcode || 'N/A'}</td></tr>
                                    <tr><th>Purpose</th><td>${ modelData?.purpose ? modelData?.purpose : 'N/A'}</td></tr>
                                    <tr><th>Visiting date</th><td>${ modelData?.visiting_date ? modelData?.visiting_date : 'N/A'}</td></tr>
                                    <tr><th>Visiting Time</th><td>${ modelData?.visiting_time || 'N/A'}</td></tr>
                                </table>
                            </div>
                        </div>
                    
                        
                    </div>
                </div>
                `;
                content += "</table>"
                $('#here_table').html(content);
                $("#DataModal").modal("show");

            });
        });
    </script>
@endpush
